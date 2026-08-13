// SPDX-License-Identifier: Apache-2.0

//! dm-thin metadata: the superblock, its devices, and their block mappings.
//!
//! A thin pool's mappings live in a **two-level btree**: the outer tree is
//! keyed by device id and its values are the roots of per-device trees;
//! each inner tree maps a device's block to the pool block backing it. That
//! shape is what makes snapshots cheap — a snapshot is a new outer entry
//! pointing at the *same* inner tree, and copy-on-write forks only the
//! nodes that actually change.
//!
//! Each inner value packs the pool block and a timestamp into one `u64`:
//! the low 24 bits are the time, the rest the block. The time is how the
//! pool knows whether a block predates a snapshot and therefore needs
//! copying before it can be written.

use crate::block::{le32, le64, read_validated};
use crate::space_map::{self, Root};
use crate::{Blocks, Error, THIN_SUPERBLOCK_CSUM_XOR, btree};

/// `THIN_SUPERBLOCK_MAGIC`.
pub const MAGIC: u64 = 27_022_010;
/// The superblock always lives at block 0.
pub const SUPERBLOCK_BLOCK: u64 = 0;
/// Bits of a mapping value given over to the timestamp.
const TIME_BITS: u32 = 24;
/// Mask selecting the timestamp out of a mapping value.
const TIME_MASK: u64 = (1 << TIME_BITS) - 1;
/// Depth bound for the mapping and details trees.
const MAX_DEPTH: usize = 16;

// Superblock field offsets, from `struct thin_disk_superblock`.
const OFF_UUID: usize = 16;
const OFF_MAGIC: usize = 32;
const OFF_VERSION: usize = 40;
const OFF_TIME: usize = 44;
const OFF_TRANS_ID: usize = 48;
const OFF_HELD_ROOT: usize = 56;
const OFF_DATA_SM_ROOT: usize = 64;
const OFF_METADATA_SM_ROOT: usize = 192;
const OFF_DATA_MAPPING_ROOT: usize = 320;
const OFF_DETAILS_ROOT: usize = 328;
const OFF_DATA_BLOCK_SIZE: usize = 336;
const OFF_METADATA_NR_BLOCKS: usize = 344;

/// A parsed thin superblock.
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Pool uuid; usually all zero.
    pub uuid: [u8; 16],
    /// Metadata format version.
    pub version: u32,
    /// The pool's current timestamp.
    pub time: u32,
    /// Transaction id, bumped on each commit.
    pub transaction_id: u64,
    /// A root held by userspace for a metadata snapshot, or zero.
    pub held_root: u64,
    /// Root of the two-level mapping btree.
    pub data_mapping_root: u64,
    /// Root of the device-details btree.
    pub device_details_root: u64,
    /// Data block size in 512-byte sectors.
    pub data_block_size: u32,
    /// Metadata device size in blocks.
    pub metadata_nr_blocks: u64,
    /// The data space map's root.
    pub data_sm: Root,
    /// The metadata space map's root.
    pub metadata_sm: Root,
}

impl Superblock {
    /// Read and validate the superblock at block 0.
    ///
    /// # Errors
    ///
    /// A checksum or location error, or [`Error::Malformed`] if the magic
    /// does not identify thin metadata.
    ///
    /// # Panics
    ///
    /// Never: the uuid slice is a fixed 16 bytes of a full block.
    pub fn read<B: Blocks + ?Sized>(blocks: &B) -> Result<Self, Error> {
        let raw = read_validated(blocks, SUPERBLOCK_BLOCK, THIN_SUPERBLOCK_CSUM_XOR)?;
        let magic = le64(&raw, OFF_MAGIC);
        if magic != MAGIC {
            return Err(Error::Malformed {
                block: SUPERBLOCK_BLOCK,
                reason: format!("magic {magic} is not thin metadata (expected {MAGIC})"),
            });
        }
        Ok(Superblock {
            uuid: raw[OFF_UUID..OFF_UUID + 16].try_into().expect("16 bytes"),
            version: le32(&raw, OFF_VERSION),
            time: le32(&raw, OFF_TIME),
            transaction_id: le64(&raw, OFF_TRANS_ID),
            held_root: le64(&raw, OFF_HELD_ROOT),
            data_mapping_root: le64(&raw, OFF_DATA_MAPPING_ROOT),
            device_details_root: le64(&raw, OFF_DETAILS_ROOT),
            data_block_size: le32(&raw, OFF_DATA_BLOCK_SIZE),
            metadata_nr_blocks: le64(&raw, OFF_METADATA_NR_BLOCKS),
            data_sm: Root::parse(&raw[OFF_DATA_SM_ROOT..])?,
            metadata_sm: Root::parse(&raw[OFF_METADATA_SM_ROOT..])?,
        })
    }

    /// Data blocks the pool covers, from the data space map.
    #[must_use]
    pub fn nr_data_blocks(&self) -> u64 {
        self.data_sm.nr_blocks
    }
}

/// One thin device's bookkeeping, from the device-details tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDetails {
    /// Blocks this device has mapped.
    pub mapped_blocks: u64,
    /// The transaction the device was created in.
    pub transaction_id: u64,
    /// The pool time when it was created.
    pub creation_time: u32,
    /// The pool time when it was last snapshotted.
    pub snapshotted_time: u32,
}

impl DeviceDetails {
    /// Byte size of the on-disk record.
    pub const SIZE: usize = 24;

    fn parse(raw: &[u8]) -> Self {
        DeviceDetails {
            mapped_blocks: le64(raw, 0),
            transaction_id: le64(raw, 8),
            creation_time: le32(raw, 16),
            snapshotted_time: le32(raw, 20),
        }
    }
}

/// One block mapping: a device block, the pool block backing it, and when
/// the mapping was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// Block within the thin device.
    pub origin_block: u64,
    /// Block within the pool's data device.
    pub data_block: u64,
    /// Pool time the mapping was made.
    pub time: u32,
}

/// Every device in the pool, by id, in ascending order.
///
/// # Errors
///
/// A structural error from the device-details tree, or
/// [`Error::Malformed`] if a record is the wrong size.
pub fn devices<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<Vec<(u64, DeviceDetails)>, Error> {
    btree::collect(blocks, superblock.device_details_root, MAX_DEPTH)?
        .iter()
        .map(|(id, value)| {
            if value.len() < DeviceDetails::SIZE {
                return Err(Error::Malformed {
                    block: superblock.device_details_root,
                    reason: format!(
                        "device {id} details are {} bytes, expected {}",
                        value.len(),
                        DeviceDetails::SIZE
                    ),
                });
            }
            Ok((*id, DeviceDetails::parse(value)))
        })
        .collect()
}

/// The mappings of device `dev_id`, in ascending origin-block order.
///
/// # Errors
///
/// [`Error::Malformed`] if the device is absent from the mapping tree, or
/// a structural error from either tree level.
///
/// # Panics
///
/// Never: the timestamp is masked to 24 bits before the conversion.
pub fn mappings<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
    dev_id: u64,
) -> Result<Vec<Mapping>, Error> {
    // The outer tree maps a device id to the root of that device's tree.
    let outer = btree::collect(blocks, superblock.data_mapping_root, MAX_DEPTH)?;
    let root = outer
        .iter()
        .find(|(id, _)| *id == dev_id)
        .map(|(_, value)| le64(value, 0))
        .ok_or_else(|| Error::Malformed {
            block: superblock.data_mapping_root,
            reason: format!("device {dev_id} has no mapping tree"),
        })?;

    let mut out = Vec::new();
    btree::walk(blocks, root, MAX_DEPTH, &mut |origin_block, value| {
        let packed = le64(value, 0);
        out.push(Mapping {
            origin_block,
            data_block: packed >> TIME_BITS,
            time: u32::try_from(packed & TIME_MASK).expect("24 bits fit u32"),
        });
        Ok(())
    })?;
    Ok(out)
}

/// A run of consecutive mappings that share a timestamp and advance both
/// the origin and data block by one — what `thin_dump` emits as a single
/// `range_mapping` rather than a row per block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// First device block in the run.
    pub origin_begin: u64,
    /// First pool block in the run.
    pub data_begin: u64,
    /// How many blocks the run covers.
    pub length: u64,
    /// The shared timestamp.
    pub time: u32,
}

/// Coalesce `mappings` into runs.
///
/// The input must be in ascending origin order, which [`mappings`]
/// guarantees.
#[must_use]
pub fn coalesce(mappings: &[Mapping]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for m in mappings {
        match runs.last_mut() {
            // Extend the current run only if this mapping continues it in
            // both address spaces and shares its time.
            Some(run)
                if run.time == m.time
                    && run.origin_begin + run.length == m.origin_block
                    && run.data_begin + run.length == m.data_block =>
            {
                run.length += 1;
            }
            _ => runs.push(Run {
                origin_begin: m.origin_block,
                data_begin: m.data_block,
                length: 1,
                time: m.time,
            }),
        }
    }
    runs
}

/// Open both of a pool's space maps.
///
/// # Errors
///
/// A structural error from either index.
pub fn space_maps<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
) -> Result<(space_map::SpaceMap, space_map::SpaceMap), Error> {
    // The data map indexes through a btree; the metadata map's index is
    // inline, because the metadata device is small enough to bound it.
    let data = space_map::SpaceMap::open(blocks, superblock.data_sm, space_map::Index::Btree)?;
    let metadata =
        space_map::SpaceMap::open(blocks, superblock.metadata_sm, space_map::Index::Inline)?;
    Ok((data, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(origin: u64, data: u64, time: u32) -> Mapping {
        Mapping {
            origin_block: origin,
            data_block: data,
            time,
        }
    }

    #[test]
    fn coalesces_a_contiguous_run() {
        let runs = coalesce(&[mapping(0, 0, 0), mapping(1, 1, 0), mapping(2, 2, 0)]);
        assert_eq!(
            runs,
            [Run {
                origin_begin: 0,
                data_begin: 0,
                length: 3,
                time: 0
            }]
        );
    }

    #[test]
    fn a_gap_in_either_address_space_breaks_the_run() {
        // Contiguous origins but a jump in data blocks is two runs, not one:
        // merging them would claim a mapping that does not exist.
        let runs = coalesce(&[mapping(0, 0, 0), mapping(1, 9, 0)]);
        assert_eq!(runs.len(), 2);
        // And contiguous data with an origin gap likewise.
        let runs = coalesce(&[mapping(0, 0, 0), mapping(5, 1, 0)]);
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn a_different_time_breaks_the_run() {
        // The timestamp drives copy-on-write decisions, so a run must not
        // span two of them even when the blocks line up.
        let runs = coalesce(&[mapping(0, 0, 0), mapping(1, 1, 1)]);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].time, 0);
        assert_eq!(runs[1].time, 1);
    }

    #[test]
    fn coalescing_nothing_yields_nothing() {
        assert_eq!(coalesce(&[]), []);
    }
}
