// SPDX-License-Identifier: Apache-2.0

//! dm-era metadata: which era each block was last written in.
//!
//! dm-era answers "what changed since era N", for incremental backup. It
//! keeps two things: an [`array`](crate::array) mapping every origin block
//! to the era it was last written in, and a btree of per-era
//! [`bitset`](crate::bitset)s recording which blocks were touched during
//! each era.
//!
//! The current era's writeset is held in the superblock rather than the
//! tree, because it is still being written to; a root of zero means it has
//! not been archived yet.

use crate::block::{le32, le64, read_validated};
use crate::space_map::Root;
use crate::{Blocks, Error, array, bitset, btree};

/// `SUPERBLOCK_MAGIC`.
pub const MAGIC: u64 = 2_126_579_579;
/// The checksum XOR identifying an era superblock.
pub const SUPERBLOCK_CSUM_XOR: u32 = 146_538_381;

// Field offsets, from `struct superblock_disk`.
const OFF_UUID: usize = 16;
const OFF_MAGIC: usize = 32;
const OFF_VERSION: usize = 40;
const OFF_SM_ROOT: usize = 44;
const OFF_DATA_BLOCK_SIZE: usize = 172;
const OFF_NR_BLOCKS: usize = 180;
const OFF_CURRENT_ERA: usize = 184;
const OFF_CURRENT_WRITESET: usize = 188;
const OFF_WRITESET_TREE_ROOT: usize = 200;
const OFF_ERA_ARRAY_ROOT: usize = 208;
const OFF_METADATA_SNAP: usize = 216;
/// Depth bound for the writeset tree.
const MAX_DEPTH: usize = 16;

/// A parsed era superblock.
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Era uuid; usually all zero.
    pub uuid: [u8; 16],
    /// Metadata format version.
    pub version: u32,
    /// Origin block size in 512-byte sectors.
    pub data_block_size: u32,
    /// Origin blocks the era array covers.
    pub nr_blocks: u32,
    /// The era currently being written.
    pub current_era: u32,
    /// Bits in the current era's writeset.
    pub current_writeset_bits: u32,
    /// Root of the current writeset, or zero when not yet archived.
    pub current_writeset_root: u64,
    /// Root of the btree of archived writesets.
    pub writeset_tree_root: u64,
    /// Root of the era array.
    pub era_array_root: u64,
    /// A held metadata snapshot, or zero.
    pub metadata_snap: u64,
    /// The metadata space map's root.
    pub metadata_sm: Root,
}

impl Superblock {
    /// Read and validate the superblock at block 0.
    ///
    /// # Errors
    ///
    /// A checksum or location error, or [`Error::Malformed`] if the magic
    /// is not an era's.
    ///
    /// # Panics
    ///
    /// Never: the uuid slice is a fixed 16 bytes of a full block.
    pub fn read<B: Blocks + ?Sized>(blocks: &B) -> Result<Self, Error> {
        let raw = read_validated(blocks, 0, SUPERBLOCK_CSUM_XOR)?;
        let magic = le64(&raw, OFF_MAGIC);
        if magic != MAGIC {
            return Err(Error::Malformed {
                block: 0,
                reason: format!("magic {magic} is not era metadata (expected {MAGIC})"),
            });
        }
        Ok(Superblock {
            uuid: raw[OFF_UUID..OFF_UUID + 16].try_into().expect("16 bytes"),
            version: le32(&raw, OFF_VERSION),
            data_block_size: le32(&raw, OFF_DATA_BLOCK_SIZE),
            nr_blocks: le32(&raw, OFF_NR_BLOCKS),
            current_era: le32(&raw, OFF_CURRENT_ERA),
            current_writeset_bits: le32(&raw, OFF_CURRENT_WRITESET),
            current_writeset_root: le64(&raw, OFF_CURRENT_WRITESET + 4),
            writeset_tree_root: le64(&raw, OFF_WRITESET_TREE_ROOT),
            era_array_root: le64(&raw, OFF_ERA_ARRAY_ROOT),
            metadata_snap: le64(&raw, OFF_METADATA_SNAP),
            metadata_sm: Root::parse(&raw[OFF_SM_ROOT..])?,
        })
    }
}

/// One era's writeset: which blocks were written during it.
#[derive(Debug, Clone)]
pub struct Writeset {
    /// The era this covers.
    pub era: u32,
    /// One entry per origin block.
    pub bits: Vec<bool>,
}

/// Every archived writeset, plus the current one when it has a root.
///
/// # Errors
///
/// A structural error from the writeset tree or any bitset.
pub fn writesets<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<Vec<Writeset>, Error> {
    let mut out = Vec::new();
    for (era, value) in btree::collect(blocks, superblock.writeset_tree_root, MAX_DEPTH)? {
        // A writeset_disk is a bit count followed by its bitset root.
        let nr_bits = u64::from(le32(&value, 0));
        let root = le64(&value, 4);
        out.push(Writeset {
            era: u32::try_from(era).unwrap_or(u32::MAX),
            bits: bitset::collect(blocks, root, nr_bits)?,
        });
    }
    // The era being written lives in the superblock until it is archived.
    if superblock.current_writeset_root != 0 {
        out.push(Writeset {
            era: superblock.current_era,
            bits: bitset::collect(
                blocks,
                superblock.current_writeset_root,
                u64::from(superblock.current_writeset_bits),
            )?,
        });
    }
    out.sort_by_key(|w| w.era);
    Ok(out)
}

/// The era each origin block was last written in, by block.
///
/// # Errors
///
/// A structural error from the era array.
pub fn era_array<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<Vec<u32>, Error> {
    let mut out = Vec::new();
    array::walk(blocks, superblock.era_array_root, &mut |_index, value| {
        out.push(le32(value, 0));
        Ok(())
    })?;
    out.truncate(usize::try_from(superblock.nr_blocks).unwrap_or(usize::MAX));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_and_checksum_xor_match_the_kernel() {
        assert_eq!(MAGIC, 2_126_579_579);
        assert_eq!(SUPERBLOCK_CSUM_XOR, 146_538_381);
    }

    #[test]
    fn a_writeset_disk_is_a_bit_count_then_a_root() {
        // Packed, so the u64 root starts at offset 4 rather than 8.
        let mut value = vec![0u8; 12];
        value[0..4].copy_from_slice(&512u32.to_le_bytes());
        value[4..12].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(le32(&value, 0), 512);
        assert_eq!(le64(&value, 4), 9);
    }
}
