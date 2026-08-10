// SPDX-License-Identifier: Apache-2.0

//! The dm-zoned on-disk metadata format — a pure-Rust `dmzadm`.
//!
//! dm-zoned is the one device-mapper target that cannot be brought up
//! without an external formatter: the kernel reads a metadata region
//! (superblocks, a chunk mapping table, and per-zone bitmaps) that it
//! never writes from scratch, so `dmzadm --format` has to run first. This
//! crate produces that region so a caller never shells out.
//!
//! Like `devmap-verity`, the byte-layout computation here is pure and
//! portable — it takes zone geometry as input and emits bytes — while the
//! geometry query (a `BLKREPORTZONE` ioctl) and the writes to the device
//! are the only Linux-coupled parts. This crate does not depend on
//! `devmap-linux`; activating the formatted device is the caller's job.
//!
//! The metadata layout is the kernel's, mirrored from
//! `drivers/md/dm-zoned-metadata.c`. Two identical metadata sets (a
//! primary and a secondary mirror) each hold, in order: a 4 KiB
//! superblock, the chunk mapping table, then the per-zone bitmaps. All
//! multi-byte fields are little-endian.

// Lint posture for a byte-format crate. The CRC seed deliberately
// truncates the u64 generation to u32, matching the kernel passing it into
// crc32_le's u32 parameter; block sizes are small compile-time constants;
// and the fixed-slice `try_into().unwrap()`s in from_block cannot panic.
#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

mod crc32;
mod layout;

pub use crc32::crc32_le;
pub use layout::{FormatOptions, Geometry, Layout, LayoutError};

#[cfg(target_os = "linux")]
mod device;
#[cfg(target_os = "linux")]
pub use device::{FormatError, format, report_zones};

/// The dm-zoned block size. Every metadata unit — superblock, mapping
/// block, bitmap block — is one of these.
pub const BLOCK_SIZE: usize = 4096;

/// `dmz_super.magic` — the ASCII bytes `D`, `Z`, `B`, `D` as a
/// little-endian `u32` (`dm-zoned-metadata.c`).
pub const MAGIC: u32 = 0x445A_4244;

/// The current on-disk format version (`DMZ_META_VER`). Version 2 adds
/// the label and the volume/device UUIDs; the kernel requires them.
pub const FORMAT_VERSION: u32 = 2;

/// The chunk mapping sentinel (`DMZ_MAP_UNMAPPED`): an entry with both
/// ids set to this maps nothing, the initial state of every chunk.
pub const MAP_UNMAPPED: u32 = u32::MAX;

/// `dmz_map` entries per mapping block: `BLOCK_SIZE / 8`.
pub const MAP_ENTRIES_PER_BLOCK: u32 = (BLOCK_SIZE as u32) / 8;

// Field offsets within the 512-byte `dmz_super`, laid out in
// `dm-zoned-metadata.c`. The struct occupies 512 bytes but is written
// into a full 4 KiB block, and the CRC covers the whole block.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_GEN: usize = 8;
const OFF_SB_BLOCK: usize = 16;
const OFF_NR_META_BLOCKS: usize = 24;
const OFF_NR_RESERVED_SEQ: usize = 28;
const OFF_NR_CHUNKS: usize = 32;
const OFF_NR_MAP_BLOCKS: usize = 36;
const OFF_NR_BITMAP_BLOCKS: usize = 40;
const OFF_CRC: usize = 44;
const OFF_LABEL: usize = 48;
const OFF_DMZ_UUID: usize = 80;
const OFF_DEV_UUID: usize = 96;

/// The `dmz_super` superblock, one per metadata set.
///
/// Fields are public because this is a wire layout: the type *is* the
/// on-disk record. [`to_block`](Superblock::to_block) serialises it (CRC
/// and all) and [`from_block`](Superblock::from_block) reads it back.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Superblock {
    /// Format version; write [`FORMAT_VERSION`].
    pub version: u32,
    /// Generation counter, bumped on every metadata commit. A fresh
    /// format writes 1. Also the CRC seed for this block.
    pub generation: u64,
    /// The absolute block number this superblock sits at — 0 for the
    /// primary, the secondary set's start block for the mirror.
    pub sb_block: u64,
    /// Blocks in one metadata set: `1 + nr_map_blocks + nr_bitmap_blocks`.
    pub nr_meta_blocks: u32,
    /// Sequential zones held in reserve for reclaim.
    pub nr_reserved_seq: u32,
    /// Chunks the volume exposes — its data-zone capacity.
    pub nr_chunks: u32,
    /// Blocks the chunk mapping table occupies.
    pub nr_map_blocks: u32,
    /// Blocks the per-zone bitmap region occupies.
    pub nr_bitmap_blocks: u32,
    /// The volume label, NUL-padded to 32 bytes.
    pub label: [u8; 32],
    /// The volume UUID (same across a volume's superblocks).
    pub dmz_uuid: [u8; 16],
    /// This device's UUID (distinct per device in a multi-device set).
    pub dev_uuid: [u8; 16],
}

impl Superblock {
    /// Serialise to a full [`BLOCK_SIZE`] block, with the CRC computed
    /// over the whole block exactly as the kernel does.
    #[must_use]
    pub fn to_block(&self) -> [u8; BLOCK_SIZE] {
        let mut b = [0u8; BLOCK_SIZE];
        b[OFF_MAGIC..][..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[OFF_VERSION..][..4].copy_from_slice(&self.version.to_le_bytes());
        b[OFF_GEN..][..8].copy_from_slice(&self.generation.to_le_bytes());
        b[OFF_SB_BLOCK..][..8].copy_from_slice(&self.sb_block.to_le_bytes());
        b[OFF_NR_META_BLOCKS..][..4].copy_from_slice(&self.nr_meta_blocks.to_le_bytes());
        b[OFF_NR_RESERVED_SEQ..][..4].copy_from_slice(&self.nr_reserved_seq.to_le_bytes());
        b[OFF_NR_CHUNKS..][..4].copy_from_slice(&self.nr_chunks.to_le_bytes());
        b[OFF_NR_MAP_BLOCKS..][..4].copy_from_slice(&self.nr_map_blocks.to_le_bytes());
        b[OFF_NR_BITMAP_BLOCKS..][..4].copy_from_slice(&self.nr_bitmap_blocks.to_le_bytes());
        b[OFF_LABEL..][..32].copy_from_slice(&self.label);
        b[OFF_DMZ_UUID..][..16].copy_from_slice(&self.dmz_uuid);
        b[OFF_DEV_UUID..][..16].copy_from_slice(&self.dev_uuid);
        // CRC field stays zero while hashing, then holds the result. The
        // kernel seeds crc32_le with the generation number.
        let crc = crc32_le(self.generation as u32, &b);
        b[OFF_CRC..][..4].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Read a superblock from a block, validating the magic and CRC.
    ///
    /// # Errors
    ///
    /// [`BadMagic`](ParseError::BadMagic) if the block is not a dm-zoned
    /// superblock, or [`BadCrc`](ParseError::BadCrc) if the stored CRC
    /// doesn't match — the kernel rejects both.
    pub fn from_block(block: &[u8; BLOCK_SIZE]) -> Result<Self, ParseError> {
        let u32_at = |off: usize| u32::from_le_bytes(block[off..][..4].try_into().unwrap());
        let u64_at = |off: usize| u64::from_le_bytes(block[off..][..8].try_into().unwrap());

        if u32_at(OFF_MAGIC) != MAGIC {
            return Err(ParseError::BadMagic);
        }
        let stored_crc = u32_at(OFF_CRC);
        let generation = u64_at(OFF_GEN);
        let mut zeroed = *block;
        zeroed[OFF_CRC..][..4].fill(0);
        if crc32_le(generation as u32, &zeroed) != stored_crc {
            return Err(ParseError::BadCrc);
        }

        let bytes = |off: usize, len: usize| {
            let mut out = vec![0u8; len];
            out.copy_from_slice(&block[off..][..len]);
            out
        };
        Ok(Superblock {
            version: u32_at(OFF_VERSION),
            generation,
            sb_block: u64_at(OFF_SB_BLOCK),
            nr_meta_blocks: u32_at(OFF_NR_META_BLOCKS),
            nr_reserved_seq: u32_at(OFF_NR_RESERVED_SEQ),
            nr_chunks: u32_at(OFF_NR_CHUNKS),
            nr_map_blocks: u32_at(OFF_NR_MAP_BLOCKS),
            nr_bitmap_blocks: u32_at(OFF_NR_BITMAP_BLOCKS),
            label: bytes(OFF_LABEL, 32).try_into().unwrap(),
            dmz_uuid: bytes(OFF_DMZ_UUID, 16).try_into().unwrap(),
            dev_uuid: bytes(OFF_DEV_UUID, 16).try_into().unwrap(),
        })
    }
}

/// Why a block failed to parse as a [`Superblock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The block does not start with [`MAGIC`].
    BadMagic,
    /// The stored CRC does not match the block contents.
    BadCrc,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            ParseError::BadMagic => "not a dm-zoned superblock (bad magic)",
            ParseError::BadCrc => "dm-zoned superblock CRC mismatch",
        })
    }
}

impl core::error::Error for ParseError {}
