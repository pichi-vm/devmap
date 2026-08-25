// SPDX-License-Identifier: Apache-2.0

//! dm-cache metadata: the superblock, its mappings, and its hints.
//!
//! A cache maps *cache* blocks to the origin blocks they hold, which is a
//! dense sequence — one entry per cache block — so unlike thin's sparse
//! mappings these live in an [`array`](crate::array) rather than a btree.
//! The policy's per-block hints live in a second array alongside.
//!
//! Two metadata versions are in use and they differ in where dirtiness is
//! recorded. Version 1 packs a dirty flag into each mapping; version 2
//! moved it out into a separate bitset so that flushing does not have to
//! rewrite the mapping array. Both are read here, because a pool created
//! by an older kernel is still perfectly valid.

use crate::block::{le32, le64, read_validated};
use crate::btree::ValueSize;
use crate::space_map::Root;
use crate::{Blocks, Error, array, bitset};

/// `CACHE_SUPERBLOCK_MAGIC`. The kernel writes it as the octal literal
/// `06142003`, which is this value — reading it as decimal `6142003`
/// would reject every real cache.
pub const MAGIC: u64 = 0o6_142_003;
/// The checksum XOR identifying a cache superblock.
pub const SUPERBLOCK_CSUM_XOR: u32 = 9_031_977;
/// Versions this reader understands.
pub const MIN_VERSION: u32 = 1;
/// The newest version this reader understands.
pub const MAX_VERSION: u32 = 2;

// Superblock field offsets, from `struct cache_disk_superblock`.
const OFF_UUID: usize = 16;
const OFF_MAGIC: usize = 32;
const OFF_VERSION: usize = 40;
const OFF_POLICY_NAME: usize = 44;
const POLICY_NAME_SIZE: usize = 16;
const OFF_POLICY_HINT_SIZE: usize = 60;
const OFF_METADATA_SM_ROOT: usize = 64;
const OFF_MAPPING_ROOT: usize = 192;
const OFF_HINT_ROOT: usize = 200;
const OFF_DISCARD_ROOT: usize = 208;
const OFF_DISCARD_BLOCK_SIZE: usize = 216;
const OFF_DISCARD_NR_BLOCKS: usize = 224;
const OFF_DATA_BLOCK_SIZE: usize = 232;
const OFF_CACHE_BLOCKS: usize = 240;
const OFF_POLICY_VERSION: usize = 272;
const OFF_DIRTY_ROOT: usize = 284;

/// A mapping is only meaningful when this bit is set.
const M_VALID: u64 = 1;
/// Version 1 records dirtiness in this bit of the mapping.
const M_DIRTY: u64 = 2;
/// Bits of a mapping value given over to flags.
const FLAG_BITS: u32 = 16;
/// A mapping is one `u64`: an origin block above the flag bits.
const MAPPING_SIZE: ValueSize = ValueSize(8);

/// A parsed cache superblock.
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Cache uuid; usually all zero.
    pub uuid: [u8; 16],
    /// Metadata format version, 1 or 2.
    pub version: u32,
    /// The cache replacement policy's name, e.g. `smq`.
    pub policy_name: String,
    /// The policy's version triple.
    pub policy_version: [u32; 3],
    /// Bytes of hint the policy stores per cache block.
    pub policy_hint_size: u32,
    /// Root of the mapping array.
    pub mapping_root: u64,
    /// Root of the hint array.
    pub hint_root: u64,
    /// Root of the discard bitset.
    pub discard_root: u64,
    /// Discard granularity in sectors.
    pub discard_block_size: u64,
    /// Blocks the discard bitset covers.
    pub discard_nr_blocks: u64,
    /// Cache block size in 512-byte sectors.
    pub data_block_size: u32,
    /// How many cache blocks the cache has.
    pub cache_blocks: u32,
    /// Root of the dirty bitset; version 2 only.
    pub dirty_root: u64,
    /// The metadata space map's root.
    pub metadata_sm: Root,
}

impl Superblock {
    /// Read and validate the superblock at block 0.
    ///
    /// # Errors
    ///
    /// A checksum or location error, [`Error::Malformed`] if the magic is
    /// not a cache's, or if the version is outside what this reader knows.
    ///
    /// # Panics
    ///
    /// Never: every slice below is a fixed span of a full block.
    pub fn read<B: Blocks + ?Sized>(blocks: &B) -> Result<Self, Error> {
        let raw = read_validated(blocks, 0, SUPERBLOCK_CSUM_XOR)?;
        let magic = le64(&raw, OFF_MAGIC);
        if magic != MAGIC {
            return Err(Error::Malformed {
                block: 0,
                reason: format!("magic {magic} is not cache metadata (expected {MAGIC})"),
            });
        }
        let version = le32(&raw, OFF_VERSION);
        if !(MIN_VERSION..=MAX_VERSION).contains(&version) {
            return Err(Error::Malformed {
                block: 0,
                reason: format!("cache metadata version {version} is not supported"),
            });
        }
        let name = &raw[OFF_POLICY_NAME..OFF_POLICY_NAME + POLICY_NAME_SIZE];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());

        Ok(Superblock {
            uuid: raw[OFF_UUID..OFF_UUID + 16].try_into().expect("16 bytes"),
            version,
            policy_name: String::from_utf8_lossy(&name[..end]).into_owned(),
            policy_version: [
                le32(&raw, OFF_POLICY_VERSION),
                le32(&raw, OFF_POLICY_VERSION + 4),
                le32(&raw, OFF_POLICY_VERSION + 8),
            ],
            policy_hint_size: le32(&raw, OFF_POLICY_HINT_SIZE),
            mapping_root: le64(&raw, OFF_MAPPING_ROOT),
            hint_root: le64(&raw, OFF_HINT_ROOT),
            discard_root: le64(&raw, OFF_DISCARD_ROOT),
            discard_block_size: le64(&raw, OFF_DISCARD_BLOCK_SIZE),
            discard_nr_blocks: le64(&raw, OFF_DISCARD_NR_BLOCKS),
            data_block_size: le32(&raw, OFF_DATA_BLOCK_SIZE),
            cache_blocks: le32(&raw, OFF_CACHE_BLOCKS),
            dirty_root: le64(&raw, OFF_DIRTY_ROOT),
            metadata_sm: Root::parse(&raw[OFF_METADATA_SM_ROOT..])?,
        })
    }
}

/// One cache block's mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The cache block.
    pub cache_block: u64,
    /// The origin block it holds.
    pub origin_block: u64,
    /// Whether the cached copy differs from the origin.
    pub dirty: bool,
}

/// Every valid mapping, in cache-block order.
///
/// Invalid entries — cache blocks holding nothing — are skipped, which is
/// what makes the result the set of *live* mappings rather than one entry
/// per cache block.
///
/// # Errors
///
/// A structural error from the mapping array or the dirty bitset.
///
/// # Panics
///
/// Never: the array is walked expecting [`MAPPING_SIZE`], so every value is
/// a whole `u64`, and a cache block index is bounded by `cache_blocks`, a
/// `u32`.
pub fn mappings<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<Vec<Mapping>, Error> {
    // Version 2 keeps dirtiness in its own bitset, so fetch it up front.
    let dirty_bits = if superblock.version >= 2 && superblock.dirty_root != 0 {
        Some(bitset::collect(
            blocks,
            superblock.dirty_root,
            u64::from(superblock.cache_blocks),
        )?)
    } else {
        None
    };

    let mut out = Vec::new();
    array::walk(
        blocks,
        superblock.mapping_root,
        MAPPING_SIZE,
        &mut |index, value| {
            let packed = le64(value, 0);
            if packed & M_VALID == 0 {
                return Ok(());
            }
            let dirty = match &dirty_bits {
                Some(bits) => bits
                    .get(usize::try_from(index).expect("cache block index fits usize"))
                    .copied()
                    .unwrap_or(false),
                // Version 1 carries the flag in the mapping itself.
                None => packed & M_DIRTY != 0,
            };
            out.push(Mapping {
                cache_block: index,
                origin_block: packed >> FLAG_BITS,
                dirty,
            });
            Ok(())
        },
    )?;
    Ok(out)
}

/// The policy hint for each cache block, in order.
///
/// A hint is opaque to this reader — only the policy that wrote it knows
/// what it means — but its width is not: the superblock records it, so the
/// array is required to agree.
///
/// # Errors
///
/// A structural error from the hint array, including a hint array whose
/// values are not `policy_hint_size` bytes wide.
pub fn hints<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<Vec<Vec<u8>>, Error> {
    if superblock.hint_root == 0 {
        return Ok(Vec::new());
    }
    let width = usize::try_from(superblock.policy_hint_size).unwrap_or(usize::MAX);
    array::collect(blocks, superblock.hint_root, ValueSize(width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_is_an_octal_literal_in_the_kernel() {
        // `#define CACHE_SUPERBLOCK_MAGIC 06142003` is octal; taking the
        // digits at face value as decimal would reject every real cache.
        assert_eq!(MAGIC, 1_623_043);
        assert_ne!(MAGIC, 6_142_003);
    }

    #[test]
    fn mapping_values_split_into_an_origin_block_and_flags() {
        // A mapping packs the origin block above 16 bits of flags.
        let packed: u64 = (99u64 << FLAG_BITS) | M_VALID | M_DIRTY;
        assert_eq!(packed >> FLAG_BITS, 99);
        assert_ne!(packed & M_VALID, 0);
        assert_ne!(packed & M_DIRTY, 0);

        let clean: u64 = (17u64 << FLAG_BITS) | M_VALID;
        assert_eq!(clean >> FLAG_BITS, 17);
        assert_eq!(clean & M_DIRTY, 0);

        // Without the valid bit the entry describes no mapping at all.
        let empty: u64 = 0;
        assert_eq!(empty & M_VALID, 0);
    }
}
