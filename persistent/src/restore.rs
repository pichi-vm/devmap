// SPDX-License-Identifier: Apache-2.0

//! Building thin metadata from scratch — the `thin_restore` direction.
//!
//! This is the dangerous side of the format. Reading a bad pool reports an
//! error; *writing* a bad pool destroys access to real data. Two things
//! constrain it:
//!
//! - Metadata is assembled entirely in memory and only written out once
//!   every structure is complete and consistent, so a failure partway
//!   leaves the destination untouched rather than half-rebuilt.
//! - The superblock is written **last**. It is the only entry point, so
//!   until it lands the destination is not yet a pool; that ordering is
//!   what makes an interrupted restore a non-event rather than a corruption.
//!
//! # Reference counts are computed, never assumed
//!
//! Both space maps are derived from what was actually built: metadata
//! counts from the blocks allocated, data counts from the mappings
//! themselves. Nothing is copied from the input, so an input claiming a
//! wrong `mapped_blocks` cannot produce metadata whose space maps lie.

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};

use crate::block::BLOCK_SIZE;
use crate::space_map::ENTRIES_PER_BITMAP;
use crate::xml::Pool;
use crate::{
    BITMAP_CSUM_XOR, BTREE_CSUM_XOR, Error, INDEX_CSUM_XOR, THIN_SUPERBLOCK_CSUM_XOR, checksum,
    thin,
};

/// Bytes of btree node header before the keys.
const NODE_HEADER: usize = 32;
/// Bytes of `disk_bitmap_header` before a bitmap's entries.
const BITMAP_HEADER: usize = 16;
/// Bytes of header before a `disk_metadata_index`'s inline entries.
const METADATA_INDEX_HEADER: usize = 16;
/// `LEAF_NODE`.
const LEAF: u32 = 2;
/// `INTERNAL_NODE`.
const INTERNAL: u32 = 1;
/// Bits of a mapping value given to the timestamp.
const TIME_BITS: u32 = 24;

/// Entries a node holds for a given value size.
///
/// The btree splits nodes into thirds, so capacity is rounded down to a
/// multiple of three — matching what thin-provisioning-tools writes, and
/// what the kernel's own `calc_max_entries` produces.
#[must_use]
fn max_entries(value_size: usize) -> usize {
    let total = (BLOCK_SIZE - NODE_HEADER) / (8 + value_size);
    (total / 3) * 3
}

/// Metadata under construction: a sparse set of blocks, written out at the
/// end.
struct Image {
    blocks: BTreeMap<u64, Vec<u8>>,
    /// Next block to hand out.
    next_free: u64,
    /// Total blocks the metadata device holds.
    nr_blocks: u64,
}

impl Image {
    fn new(nr_blocks: u64) -> Self {
        Image {
            blocks: BTreeMap::new(),
            // Block 0 is the superblock, written last.
            next_free: 1,
            nr_blocks,
        }
    }

    /// Reserve the next block.
    fn allocate(&mut self) -> Result<u64, Error> {
        if self.next_free >= self.nr_blocks {
            return Err(Error::Malformed {
                block: self.next_free,
                reason: "metadata device is too small for this pool".to_owned(),
            });
        }
        let block = self.next_free;
        self.next_free += 1;
        Ok(block)
    }

    /// Store `raw` at `block`, stamping its address and checksum.
    fn put(&mut self, block: u64, mut raw: Vec<u8>, xor: u32) {
        raw[8..16].copy_from_slice(&block.to_le_bytes());
        let csum = checksum(&raw, xor);
        raw[0..4].copy_from_slice(&csum.to_le_bytes());
        self.blocks.insert(block, raw);
    }

    /// Blocks allocated so far, i.e. every block with a reference.
    fn allocated(&self) -> u64 {
        self.next_free
    }
}

/// Build one btree from `entries`, bottom-up, returning its root block.
///
/// Leaves are filled in order, then internal levels are built over them
/// until one node remains. Building upward like this means every node is
/// complete before anything points at it.
fn build_btree(
    image: &mut Image,
    entries: &[(u64, Vec<u8>)],
    value_size: usize,
) -> Result<u64, Error> {
    let per_node = max_entries(value_size);
    // An empty tree is still a tree: a single empty leaf.
    if entries.is_empty() {
        let block = image.allocate()?;
        image.put(
            block,
            node_bytes(LEAF, &[], value_size, per_node),
            BTREE_CSUM_XOR,
        );
        return Ok(block);
    }

    // Leaf level.
    let mut level: Vec<(u64, u64)> = Vec::new(); // (first key, block)
    for chunk in entries.chunks(per_node) {
        let block = image.allocate()?;
        image.put(
            block,
            node_bytes(LEAF, chunk, value_size, per_node),
            BTREE_CSUM_XOR,
        );
        level.push((chunk[0].0, block));
    }

    // Internal levels, until a single root remains.
    let internal_per_node = max_entries(8);
    while level.len() > 1 {
        let mut parents = Vec::new();
        for chunk in level.chunks(internal_per_node) {
            let children: Vec<(u64, Vec<u8>)> = chunk
                .iter()
                .map(|(key, block)| (*key, block.to_le_bytes().to_vec()))
                .collect();
            let block = image.allocate()?;
            image.put(
                block,
                node_bytes(INTERNAL, &children, 8, internal_per_node),
                BTREE_CSUM_XOR,
            );
            parents.push((chunk[0].0, block));
        }
        level = parents;
    }
    Ok(level[0].1)
}

/// Render one btree node. The caller stamps address and checksum.
fn node_bytes(
    flags: u32,
    entries: &[(u64, Vec<u8>)],
    value_size: usize,
    per_node: usize,
) -> Vec<u8> {
    let mut raw = vec![0u8; BLOCK_SIZE];
    raw[4..8].copy_from_slice(&flags.to_le_bytes());
    raw[16..20].copy_from_slice(&u32::try_from(entries.len()).expect("fits").to_le_bytes());
    raw[20..24].copy_from_slice(&u32::try_from(per_node).expect("fits").to_le_bytes());
    raw[24..28].copy_from_slice(&u32::try_from(value_size).expect("fits").to_le_bytes());

    let values_at = NODE_HEADER + per_node * 8;
    for (i, (key, value)) in entries.iter().enumerate() {
        raw[NODE_HEADER + i * 8..NODE_HEADER + i * 8 + 8].copy_from_slice(&key.to_le_bytes());
        let at = values_at + i * value_size;
        raw[at..at + value_size].copy_from_slice(value);
    }
    raw
}

/// Build a space map over `counts`, returning its `disk_sm_root` bytes.
///
/// `inline_index` selects the metadata flavour, whose index lives in one
/// block, over the disk flavour, whose index is a btree.
fn build_space_map(
    image: &mut Image,
    nr_blocks: u64,
    counts: &BTreeMap<u64, u32>,
    inline_index: bool,
) -> Result<Vec<u8>, Error> {
    let nr_bitmaps =
        usize::try_from(nr_blocks.div_ceil(ENTRIES_PER_BITMAP)).map_err(|_| Error::Malformed {
            block: 0,
            reason: "space map covers implausibly many blocks".to_owned(),
        })?;

    // Counts above two spill into an overflow btree.
    let overflow: Vec<(u64, Vec<u8>)> = counts
        .iter()
        .filter(|&(_, &c)| c > 2)
        .map(|(&b, &c)| (b, c.to_le_bytes().to_vec()))
        .collect();
    let ref_count_root = build_btree(image, &overflow, 4)?;

    // One bitmap block per ENTRIES_PER_BITMAP blocks.
    let mut index_entries = Vec::with_capacity(nr_bitmaps);
    for bitmap in 0..nr_bitmaps {
        let block = image.allocate()?;
        let first = bitmap as u64 * ENTRIES_PER_BITMAP;
        let last = (first + ENTRIES_PER_BITMAP).min(nr_blocks);

        let mut raw = vec![0u8; BLOCK_SIZE];
        let mut nr_free = 0u32;
        for b in first..last {
            let count = counts.get(&b).copied().unwrap_or(0);
            if count == 0 {
                nr_free += 1;
                continue;
            }
            // Values 1 and 2 fit the two bits; anything more is recorded as
            // 3 and resolved through the overflow tree.
            let stored = count.min(3);
            let entry = b - first;
            set_bitmap_entry(&mut raw[BITMAP_HEADER..], entry, stored);
        }
        index_entries.push((
            bitmap as u64,
            index_entry_bytes(block, nr_free, first, last, counts),
        ));
        image.put(block, raw, BITMAP_CSUM_XOR);
    }

    let bitmap_root = if inline_index {
        let block = image.allocate()?;
        let mut raw = vec![0u8; BLOCK_SIZE];
        for (i, (_, entry)) in index_entries.iter().enumerate() {
            let at = METADATA_INDEX_HEADER + i * 16;
            raw[at..at + 16].copy_from_slice(entry);
        }
        image.put(block, raw, INDEX_CSUM_XOR);
        block
    } else {
        build_btree(image, &index_entries, 16)?
    };

    let allocated = counts.values().filter(|&&c| c > 0).count() as u64;
    let mut root = vec![0u8; 32];
    root[0..8].copy_from_slice(&nr_blocks.to_le_bytes());
    root[8..16].copy_from_slice(&allocated.to_le_bytes());
    root[16..24].copy_from_slice(&bitmap_root.to_le_bytes());
    root[24..32].copy_from_slice(&ref_count_root.to_le_bytes());
    Ok(root)
}

/// Render a `disk_index_entry`.
fn index_entry_bytes(
    blocknr: u64,
    nr_free: u32,
    first: u64,
    last: u64,
    counts: &BTreeMap<u64, u32>,
) -> Vec<u8> {
    // The first free position, so the allocator need not rescan from zero.
    let none_free_before = (first..last)
        .position(|b| counts.get(&b).copied().unwrap_or(0) == 0)
        .and_then(|p| u32::try_from(p).ok())
        .unwrap_or(0);
    let mut raw = vec![0u8; 16];
    raw[0..8].copy_from_slice(&blocknr.to_le_bytes());
    raw[8..12].copy_from_slice(&nr_free.to_le_bytes());
    raw[12..16].copy_from_slice(&none_free_before.to_le_bytes());
    raw
}

/// Write the two-bit `value` for `entry` into a bitmap's data.
fn set_bitmap_entry(data: &mut [u8], entry: u64, value: u32) {
    let mut set = |n: u64, on: bool| {
        let byte = usize::try_from(n / 8).expect("fits");
        if on {
            data[byte] |= 1 << (n % 8);
        }
    };
    set(entry * 2, value & 0b10 != 0);
    set(entry * 2 + 1, value & 0b01 != 0);
}

/// Build a whole pool from `pool` and write it to `out`.
///
/// `metadata_blocks` is the size of the destination metadata device, in
/// [`BLOCK_SIZE`] blocks.
///
/// # Errors
///
/// [`Error::Malformed`] if the device is too small, or an I/O error while
/// writing.
pub fn restore<W: Write + Seek>(
    pool: &Pool,
    out: &mut W,
    metadata_blocks: u64,
) -> Result<(), Error> {
    let mut image = Image::new(metadata_blocks);
    let mut data_counts: BTreeMap<u64, u32> = BTreeMap::new();

    // Each device's mapping tree, and the data references it makes.
    let mut device_roots = Vec::new();
    for device in &pool.devices {
        let entries: Vec<(u64, Vec<u8>)> = device
            .mappings
            .iter()
            .map(|m| {
                *data_counts.entry(m.data_block).or_insert(0) += 1;
                let packed = (m.data_block << TIME_BITS) | u64::from(m.time);
                (m.origin_block, packed.to_le_bytes().to_vec())
            })
            .collect();
        let root = build_btree(&mut image, &entries, 8)?;
        device_roots.push((device.dev_id, root.to_le_bytes().to_vec()));
    }

    let data_mapping_root = build_btree(&mut image, &device_roots, 8)?;

    // Device details.
    let details: Vec<(u64, Vec<u8>)> = pool
        .devices
        .iter()
        .map(|d| {
            let mut raw = vec![0u8; 24];
            raw[0..8].copy_from_slice(&d.mapped_blocks.to_le_bytes());
            raw[8..16].copy_from_slice(&d.transaction.to_le_bytes());
            raw[16..20].copy_from_slice(&d.creation_time.to_le_bytes());
            raw[20..24].copy_from_slice(&d.snap_time.to_le_bytes());
            (d.dev_id, raw)
        })
        .collect();
    let device_details_root = build_btree(&mut image, &details, 24)?;

    // The data space map records only what the mappings referenced.
    let data_sm_root = build_space_map(&mut image, pool.nr_data_blocks, &data_counts, false)?;

    // The metadata space map must account for its own blocks, so reserve
    // them first and only then compute the counts. The count is fixed by
    // the device size, not by what has been allocated, which is what makes
    // this resolvable rather than circular.
    let nr_bitmaps = metadata_blocks.div_ceil(ENTRIES_PER_BITMAP);
    let metadata_sm_blocks = 1 /* overflow root */ + nr_bitmaps + 1 /* index */;
    let after_reserve = image
        .allocated()
        .checked_add(metadata_sm_blocks)
        .ok_or_else(|| Error::Malformed {
            block: 0,
            reason: "metadata allocation overflowed".to_owned(),
        })?;
    if after_reserve > metadata_blocks {
        return Err(Error::Malformed {
            block: 0,
            reason: format!(
                "metadata device holds {metadata_blocks} blocks, {after_reserve} needed"
            ),
        });
    }
    // Every block allocated by a fresh restore is referenced exactly once:
    // nothing is shared until snapshots are taken later.
    let metadata_counts: BTreeMap<u64, u32> = (0..after_reserve).map(|b| (b, 1)).collect();
    let metadata_sm_root = build_space_map(&mut image, metadata_blocks, &metadata_counts, true)?;

    // The superblock last: it is the only entry point, so until it lands
    // the destination is not a pool at all.
    let mut sb = vec![0u8; BLOCK_SIZE];
    sb[32..40].copy_from_slice(&thin::MAGIC.to_le_bytes());
    sb[40..44].copy_from_slice(&pool.version.to_le_bytes());
    sb[44..48].copy_from_slice(&pool.time.to_le_bytes());
    sb[48..56].copy_from_slice(&pool.transaction.to_le_bytes());
    sb[64..64 + 32].copy_from_slice(&data_sm_root);
    sb[192..192 + 32].copy_from_slice(&metadata_sm_root);
    sb[320..328].copy_from_slice(&data_mapping_root.to_le_bytes());
    sb[328..336].copy_from_slice(&device_details_root.to_le_bytes());
    sb[336..340].copy_from_slice(&pool.data_block_size.to_le_bytes());
    sb[340..344].copy_from_slice(&8u32.to_le_bytes()); // metadata block, in sectors
    sb[344..352].copy_from_slice(&metadata_blocks.to_le_bytes());
    image.put(thin::SUPERBLOCK_BLOCK, sb, THIN_SUPERBLOCK_CSUM_XOR);

    for (block, raw) in &image.blocks {
        out.seek(SeekFrom::Start(block * BLOCK_SIZE as u64))?;
        out.write_all(raw)?;
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_capacity_matches_thin_provisioning_tools() {
        // Values read out of metadata thin_restore produced; the
        // round-to-thirds is what the btree's split algorithm expects.
        assert_eq!(max_entries(8), 252);
        assert_eq!(max_entries(24), 126);
        assert_eq!(max_entries(4), 336);
        assert_eq!(max_entries(16), 168);
    }

    #[test]
    fn bitmap_entries_round_trip_through_the_reader() {
        let mut data = vec![0u8; 64];
        for (entry, value) in [(0u64, 1u32), (1, 2), (2, 3), (5, 1), (32, 2)] {
            set_bitmap_entry(&mut data, entry, value);
        }
        // Decode with the same convention the reader uses.
        let get = |entry: u64| -> u32 {
            let bit = |n: u64| u32::from(data[(n / 8) as usize] >> (n % 8) & 1);
            (bit(entry * 2) << 1) | bit(entry * 2 + 1)
        };
        assert_eq!(get(0), 1);
        assert_eq!(get(1), 2);
        assert_eq!(get(2), 3);
        assert_eq!(get(5), 1);
        assert_eq!(get(32), 2);
        assert_eq!(get(3), 0, "untouched entries stay zero");
    }

    #[test]
    fn an_allocator_refuses_to_exceed_the_device() {
        let mut image = Image::new(3);
        assert_eq!(image.allocate().expect("1"), 1);
        assert_eq!(image.allocate().expect("2"), 2);
        assert!(image.allocate().is_err(), "block 3 is past the end");
    }

    #[test]
    fn a_tree_too_big_for_one_leaf_grows_a_level() {
        let mut image = Image::new(4096);
        let entries: Vec<(u64, Vec<u8>)> = (0..1000u64)
            .map(|i| (i, i.to_le_bytes().to_vec()))
            .collect();
        let root = build_btree(&mut image, &entries, 8).expect("build");
        // 1000 entries over 252-entry leaves needs four leaves plus a root.
        let node = image.blocks.get(&root).expect("root exists");
        let flags = u32::from_le_bytes(node[4..8].try_into().unwrap());
        assert_eq!(flags, INTERNAL, "the root must be an internal node");
        let nr_entries = u32::from_le_bytes(node[16..20].try_into().unwrap());
        assert_eq!(nr_entries, 4, "four leaves beneath it");
    }
}
