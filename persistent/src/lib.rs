// SPDX-License-Identifier: Apache-2.0

//! The **dm persistent-data** metadata format — the immutable
//! copy-on-write block store that dm-thin, dm-cache and dm-era all keep
//! their metadata in (`drivers/md/persistent-data` in the kernel).
//!
//! Because the three targets share this one library, a reader for it is a
//! reader for all three: they differ only in their superblock and in the
//! value types their btrees carry.
//!
//! # Shape of the format
//!
//! Metadata is a sequence of fixed [`BLOCK_SIZE`] blocks. Every block
//! begins with a CRC32C checksum and the block's own address, and both are
//! verified on read — so a block that was torn, misdirected, or written to
//! the wrong place is caught rather than interpreted.
//!
//! On top of that sit two structures:
//!
//! - **btrees** ([`btree`]) mapping `u64` keys to fixed-size values, used
//!   for everything from block mappings to device details;
//! - **space maps**, which record how many references each block has, so
//!   that copy-on-write updates can share unchanged subtrees.
//!
//! # Checksums
//!
//! CRC32C seeded with all-ones over everything after the checksum field,
//! then combined by XOR with a per-structure constant, which is what stops a block
//! of one kind being silently accepted where another kind was expected.

pub mod block;
pub mod btree;

pub use block::{BLOCK_SIZE, Blocks};

/// The checksum XOR identifying a btree node.
pub const BTREE_CSUM_XOR: u32 = 121_107;
/// The checksum XOR identifying a space-map bitmap block.
pub const BITMAP_CSUM_XOR: u32 = 240_779;
/// The checksum XOR identifying a space-map index block.
pub const INDEX_CSUM_XOR: u32 = 160_478;
/// The checksum XOR identifying a thin superblock.
pub const THIN_SUPERBLOCK_CSUM_XOR: u32 = 160_774;
/// The checksum XOR identifying an array block.
pub const ARRAY_CSUM_XOR: u32 = 595_846_735;

/// Why metadata could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A block's checksum did not match its contents.
    #[error("block {block}: checksum mismatch (stored {stored:#010x}, computed {computed:#010x})")]
    BadChecksum {
        /// The block that failed.
        block: u64,
        /// The checksum the block claims.
        stored: u32,
        /// The checksum its bytes actually produce.
        computed: u32,
    },

    /// A block records a different address than the one it was read from,
    /// which means it was written to the wrong place or is a stale copy.
    #[error("block {block}: claims to be block {claimed}")]
    WrongLocation {
        /// Where the block was read from.
        block: u64,
        /// Where the block says it lives.
        claimed: u64,
    },

    /// A structure's fields are internally inconsistent.
    #[error("block {block}: {reason}")]
    Malformed {
        /// The offending block.
        block: u64,
        /// What was wrong.
        reason: String,
    },

    /// A read went past the end of the metadata.
    #[error("block {0} is beyond the end of the metadata")]
    OutOfRange(u64),

    /// Reading the device failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The checksum of a metadata block: CRC32C over everything after the
/// 4-byte checksum field, combined by XOR with the per-structure constant.
///
/// The kernel seeds CRC32C with all-ones and does not apply the final
/// complement that the usual CRC-32C definition does, so the standard
/// result is complemented back here before the XOR.
#[must_use]
pub fn checksum(block: &[u8], xor: u32) -> u32 {
    (crc32c::crc32c(&block[4..]) ^ 0xFFFF_FFFF) ^ xor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_stable_and_xor_separated() {
        let block = vec![0xA5u8; BLOCK_SIZE];
        let a = checksum(&block, BTREE_CSUM_XOR);
        let b = checksum(&block, BITMAP_CSUM_XOR);
        assert_eq!(a, checksum(&block, BTREE_CSUM_XOR), "deterministic");
        assert_ne!(
            a, b,
            "the same bytes must checksum differently per structure kind"
        );
        // The XOR is the only difference, by construction.
        assert_eq!(a ^ b, BTREE_CSUM_XOR ^ BITMAP_CSUM_XOR);
    }

    #[test]
    fn checksum_covers_everything_after_the_field() {
        let mut block = vec![0u8; BLOCK_SIZE];
        let base = checksum(&block, BTREE_CSUM_XOR);
        // A change inside the checksum field itself is not covered...
        block[0] = 0xFF;
        assert_eq!(checksum(&block, BTREE_CSUM_XOR), base);
        // ...but the very next byte is.
        block[4] = 0xFF;
        assert_ne!(checksum(&block, BTREE_CSUM_XOR), base);
    }
}
