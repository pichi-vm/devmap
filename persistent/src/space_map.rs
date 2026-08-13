// SPDX-License-Identifier: Apache-2.0

//! Space maps: how many references each block has.
//!
//! Because metadata is copy-on-write, an unchanged subtree can be shared by
//! several roots — a snapshot and its origin, or successive transactions.
//! The space map is what makes that safe: it records a reference count per
//! block, so a block is only reusable once nothing points at it any more.
//!
//! Counts are stored in two tiers. A bitmap holds two bits per block, which
//! covers the overwhelmingly common counts 0, 1 and 2; the value 3 means
//! "more than two", and the real count then lives in a separate btree. This
//! keeps the hot representation compact.
//!
//! There are two index flavours. A **metadata** space map keeps its index
//! inline in one block (255 entries, enough because metadata is bounded); a
//! **disk** space map, which can cover far more blocks, keeps its index in a
//! btree.

use crate::block::{BLOCK_SIZE, Blocks, le32, le64, read_validated};
use crate::{BITMAP_CSUM_XOR, Error, INDEX_CSUM_XOR, btree};

/// Byte size of a `disk_sm_root`, as embedded in a superblock.
pub const ROOT_SIZE: usize = 32;
/// Byte size of a `disk_bitmap_header`, which precedes the bitmap data.
const BITMAP_HEADER_SIZE: usize = 16;
/// Byte size of a `disk_index_entry`.
const INDEX_ENTRY_SIZE: usize = 16;
/// Bytes of header before the inline index of a `disk_metadata_index`.
const METADATA_INDEX_HEADER: usize = 16;
/// A metadata space map's index holds at most this many entries inline.
const MAX_METADATA_BITMAPS: usize = 255;
/// Blocks covered by one bitmap block: four 2-bit entries per byte.
pub const ENTRIES_PER_BITMAP: u64 = (BLOCK_SIZE as u64 - BITMAP_HEADER_SIZE as u64) * 4;
/// The bitmap value meaning "more than two references; see the btree".
const REF_COUNT_MANY: u32 = 3;

/// The root of a space map, as stored in a superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Root {
    /// Blocks the map covers.
    pub nr_blocks: u64,
    /// Blocks currently allocated (reference count above zero).
    pub nr_allocated: u64,
    /// Root of the bitmap index — a block for a metadata map, a btree root
    /// for a disk map.
    pub bitmap_root: u64,
    /// Root of the btree holding counts above two.
    pub ref_count_root: u64,
}

impl Root {
    /// Parse a `disk_sm_root` from the start of `raw`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `raw` is shorter than [`ROOT_SIZE`].
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < ROOT_SIZE {
            return Err(Error::Malformed {
                block: 0,
                reason: format!("space map root needs {ROOT_SIZE} bytes, got {}", raw.len()),
            });
        }
        Ok(Root {
            nr_blocks: le64(raw, 0),
            nr_allocated: le64(raw, 8),
            bitmap_root: le64(raw, 16),
            ref_count_root: le64(raw, 24),
        })
    }
}

/// Where a space map keeps its bitmap index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    /// Inline in a single block — used by metadata space maps.
    Inline,
    /// In a btree — used by data space maps, which cover more blocks.
    Btree,
}

/// One `disk_index_entry`: where a bitmap lives and how free it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// The block holding this bitmap.
    pub blocknr: u64,
    /// Free entries within it.
    pub nr_free: u32,
    /// No entry below this position is free.
    pub none_free_before: u32,
}

impl IndexEntry {
    fn parse(raw: &[u8]) -> Self {
        IndexEntry {
            blocknr: le64(raw, 0),
            nr_free: le32(raw, 8),
            none_free_before: le32(raw, 12),
        }
    }
}

/// An opened space map: its root plus the resolved bitmap index.
#[derive(Debug)]
pub struct SpaceMap {
    /// The root this map was opened from.
    pub root: Root,
    /// The bitmap index, one entry per bitmap block.
    pub index: Vec<IndexEntry>,
}

impl SpaceMap {
    /// Open the space map described by `root`, reading its index.
    ///
    /// # Errors
    ///
    /// A checksum, location, or structural error from the index.
    pub fn open<B: Blocks + ?Sized>(blocks: &B, root: Root, index: Index) -> Result<Self, Error> {
        let entries = match index {
            Index::Inline => {
                let raw = read_validated(blocks, root.bitmap_root, INDEX_CSUM_XOR)?;
                // Only the entries the map actually needs are meaningful.
                let needed =
                    usize::try_from(root.nr_blocks.div_ceil(ENTRIES_PER_BITMAP)).map_err(|_| {
                        Error::Malformed {
                            block: root.bitmap_root,
                            reason: "space map covers implausibly many blocks".to_owned(),
                        }
                    })?;
                if needed > MAX_METADATA_BITMAPS {
                    return Err(Error::Malformed {
                        block: root.bitmap_root,
                        reason: format!(
                            "{needed} bitmaps needed but an inline index holds {MAX_METADATA_BITMAPS}"
                        ),
                    });
                }
                (0..needed)
                    .map(|i| {
                        IndexEntry::parse(&raw[METADATA_INDEX_HEADER + i * INDEX_ENTRY_SIZE..])
                    })
                    .collect()
            }
            Index::Btree => btree::collect(blocks, root.bitmap_root, 16)?
                .iter()
                .map(|(_, value)| IndexEntry::parse(value))
                .collect(),
        };
        Ok(SpaceMap {
            root,
            index: entries,
        })
    }

    /// The reference count of `block`.
    ///
    /// Reads the two-bit entry, and falls back to the overflow btree when
    /// it says the count exceeds two.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] if `block` is outside the map, or a structural
    /// error from the bitmap or overflow btree.
    ///
    /// # Panics
    ///
    /// Never: the bitmap index is bounded by `nr_blocks`, checked above.
    pub fn ref_count<B: Blocks + ?Sized>(&self, blocks: &B, block: u64) -> Result<u32, Error> {
        if block >= self.root.nr_blocks {
            return Err(Error::OutOfRange(block));
        }
        let which = usize::try_from(block / ENTRIES_PER_BITMAP).expect("bitmap index fits usize");
        let entry = self.index.get(which).ok_or(Error::OutOfRange(block))?;
        let raw = read_validated(blocks, entry.blocknr, BITMAP_CSUM_XOR)?;

        let low = bitmap_entry(&raw[BITMAP_HEADER_SIZE..], block % ENTRIES_PER_BITMAP);
        if low != REF_COUNT_MANY {
            return Ok(low);
        }
        // Counts above two live in the overflow btree, keyed by block.
        for (key, value) in btree::collect(blocks, self.root.ref_count_root, 16)? {
            if key == block {
                return Ok(le32(&value, 0));
            }
        }
        Err(Error::Malformed {
            block,
            reason: "bitmap says the count exceeds two but the overflow btree has no entry"
                .to_owned(),
        })
    }
}

/// The two-bit value for `entry` within a bitmap's data.
///
/// Entries are packed two bits each into little-endian 64-bit words. The
/// high bit of entry *n* lands at bit index `2n` and the low bit at `2n+1`,
/// counting bits little-endian — which is why this reduces to a pair of
/// plain bit tests rather than any word-level shuffling.
fn bitmap_entry(data: &[u8], entry: u64) -> u32 {
    let bit = |n: u64| -> u32 {
        let byte = usize::try_from(n / 8).expect("bit index fits usize");
        u32::from(data.get(byte).copied().unwrap_or(0) >> (n % 8) & 1)
    };
    (bit(entry * 2) << 1) | bit(entry * 2 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_root() {
        let mut raw = [0u8; ROOT_SIZE];
        raw[0..8].copy_from_slice(&4096u64.to_le_bytes());
        raw[8..16].copy_from_slice(&4u64.to_le_bytes());
        raw[16..24].copy_from_slice(&7u64.to_le_bytes());
        raw[24..32].copy_from_slice(&6u64.to_le_bytes());
        let root = Root::parse(&raw).expect("parse");
        assert_eq!(root.nr_blocks, 4096);
        assert_eq!(root.nr_allocated, 4);
        assert_eq!(root.bitmap_root, 7);
        assert_eq!(root.ref_count_root, 6);
    }

    #[test]
    fn rejects_a_short_root() {
        assert!(Root::parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn reads_two_bit_entries() {
        // Entry n occupies little-endian bits 2n (high) and 2n+1 (low), so
        // byte 0 holds entries 0..=3.
        let mut data = vec![0u8; 64];
        // entry 0 = 1 (binary 01): high bit clear, low bit set -> bit 1.
        data[0] |= 1 << 1;
        // entry 1 = 2 (binary 10): high bit set -> bit 2.
        data[0] |= 1 << 2;
        // entry 2 = 3 (binary 11): bits 4 and 5.
        data[0] |= (1 << 4) | (1 << 5);
        assert_eq!(bitmap_entry(&data, 0), 1);
        assert_eq!(bitmap_entry(&data, 1), 2);
        assert_eq!(bitmap_entry(&data, 2), 3);
        assert_eq!(bitmap_entry(&data, 3), 0);
    }

    #[test]
    fn entries_span_byte_and_word_boundaries() {
        let mut data = vec![0u8; 64];
        // Entry 4 starts at bit 8, i.e. byte 1.
        data[1] |= 1 << 1;
        assert_eq!(bitmap_entry(&data, 4), 1);
        // Entry 32 starts at bit 64, i.e. the second 64-bit word.
        data[8] |= 1 << 0;
        assert_eq!(bitmap_entry(&data, 32), 2);
    }

    #[test]
    fn reads_past_the_end_as_zero_rather_than_panicking() {
        // A short or truncated bitmap must not crash the reader.
        assert_eq!(bitmap_entry(&[], 0), 0);
        assert_eq!(bitmap_entry(&[0xFF], 1000), 0);
    }
}
