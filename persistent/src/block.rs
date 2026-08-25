// SPDX-License-Identifier: Apache-2.0

//! The metadata block layer: fixed-size blocks, each self-describing.
//!
//! Every block carries its own checksum *and* its own address. Verifying
//! both on read is what makes the format robust: a torn write fails the
//! checksum, and a block that was written to the wrong place — or a stale
//! copy resurrected from elsewhere — fails the address check even though
//! its checksum is perfectly valid.

use crate::{Error, checksum};

/// Metadata blocks are always 4 KiB.
pub const BLOCK_SIZE: usize = 4096;
/// Offset of the `blocknr` field, which follows `csum` and `flags`.
const OFF_BLOCKNR: usize = 8;

/// A source of metadata blocks.
///
/// Implemented for an in-memory image and for a file, so the same readers
/// work against a real metadata device and against a test fixture.
pub trait Blocks {
    /// Read block `nr` in full.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfRange`] past the end — every implementation reports
    /// that the same way, so a diagnostic names the offending block whether
    /// the metadata was read from a device or from memory — or the
    /// underlying I/O error.
    fn read_block(&self, nr: u64) -> Result<Vec<u8>, Error>;
}

impl Blocks for [u8] {
    fn read_block(&self, nr: u64) -> Result<Vec<u8>, Error> {
        let start = usize::try_from(nr)
            .ok()
            .and_then(|n| n.checked_mul(BLOCK_SIZE))
            .ok_or(Error::OutOfRange(nr))?;
        let end = start.checked_add(BLOCK_SIZE).ok_or(Error::OutOfRange(nr))?;
        self.get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or(Error::OutOfRange(nr))
    }
}

impl Blocks for std::fs::File {
    fn read_block(&self, nr: u64) -> Result<Vec<u8>, Error> {
        use std::os::unix::fs::FileExt as _;
        let offset = nr
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or(Error::OutOfRange(nr))?;
        let mut buf = vec![0u8; BLOCK_SIZE];
        // A short read is how a file or block device spells "past the end",
        // and it is the same fault the in-memory impl reports as
        // `OutOfRange`. Left as the bare `io::Error` it becomes "failed to
        // fill whole buffer", which names neither the block nor the cause —
        // and a dangling pointer in damaged metadata is exactly when the
        // block number is worth having.
        self.read_exact_at(&mut buf, offset).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::OutOfRange(nr)
            } else {
                Error::Io(e)
            }
        })?;
        Ok(buf)
    }
}

/// Read block `nr` and verify both its checksum and its self-recorded
/// address against `xor`, the constant identifying the kind of structure
/// the caller expects to find there.
///
/// # Errors
///
/// [`Error::BadChecksum`] if the block is corrupt, or
/// [`Error::WrongLocation`] if it belongs somewhere else — which a valid
/// checksum alone would not catch.
///
/// # Panics
///
/// Never: `read_block` always yields a full [`BLOCK_SIZE`] block, so the
/// fixed-offset field reads below are always in bounds.
pub fn read_validated<B: Blocks + ?Sized>(blocks: &B, nr: u64, xor: u32) -> Result<Vec<u8>, Error> {
    read_validated_at(blocks, nr, xor, OFF_BLOCKNR)
}

/// As [`read_validated`], but for structures that record their address
/// somewhere other than offset 8.
///
/// Most persistent-data structures put `blocknr` right after `csum` and
/// `flags`, but an array block orders its header differently and keeps it
/// at offset 16. Getting that wrong would either reject every array block
/// or, worse, compare against whatever field happens to sit at offset 8.
///
/// # Errors
///
/// As [`read_validated`].
///
/// # Panics
///
/// Never for `blocknr_offset + 8 <= BLOCK_SIZE`, which every caller
/// satisfies with a compile-time constant.
pub fn read_validated_at<B: Blocks + ?Sized>(
    blocks: &B,
    nr: u64,
    xor: u32,
    blocknr_offset: usize,
) -> Result<Vec<u8>, Error> {
    let raw = blocks.read_block(nr)?;
    let stored = u32::from_le_bytes(raw[0..4].try_into().expect("4 bytes"));
    let computed = checksum(&raw, xor);
    if stored != computed {
        return Err(Error::BadChecksum {
            block: nr,
            stored,
            computed,
        });
    }
    let claimed = u64::from_le_bytes(
        raw[blocknr_offset..blocknr_offset + 8]
            .try_into()
            .expect("8 bytes"),
    );
    if claimed != nr {
        return Err(Error::WrongLocation { block: nr, claimed });
    }
    Ok(raw)
}

/// Read a little-endian `u64` at `offset`.
///
/// # Panics
///
/// If `offset + 8` exceeds `raw`; callers work within a [`BLOCK_SIZE`]
/// block at fixed offsets, so this cannot happen in practice.
#[must_use]
pub fn le64(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().expect("8 bytes"))
}

/// Read a little-endian `u32` at `offset`.
///
/// # Panics
///
/// As [`le64`].
#[must_use]
pub fn le32(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().expect("4 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BTREE_CSUM_XOR;

    /// Build a block that passes validation at `nr`.
    fn valid_block(nr: u64) -> Vec<u8> {
        let mut raw = vec![0u8; BLOCK_SIZE];
        raw[OFF_BLOCKNR..OFF_BLOCKNR + 8].copy_from_slice(&nr.to_le_bytes());
        let csum = checksum(&raw, BTREE_CSUM_XOR);
        raw[0..4].copy_from_slice(&csum.to_le_bytes());
        raw
    }

    #[test]
    fn reads_and_validates_a_well_formed_block() {
        let mut image = vec![0u8; BLOCK_SIZE * 3];
        image[BLOCK_SIZE * 2..].copy_from_slice(&valid_block(2));
        let got = read_validated(image.as_slice(), 2, BTREE_CSUM_XOR).expect("validate");
        assert_eq!(le64(&got, OFF_BLOCKNR), 2);
    }

    #[test]
    fn rejects_a_corrupt_block() {
        let mut image = valid_block(0);
        image[100] ^= 0xFF;
        assert!(matches!(
            read_validated(image.as_slice(), 0, BTREE_CSUM_XOR),
            Err(Error::BadChecksum { .. })
        ));
    }

    #[test]
    fn rejects_a_block_from_the_wrong_place() {
        // Checksum-valid, but built for block 7 and found at block 0: a
        // misdirected or stale write, which the checksum alone misses.
        let image = valid_block(7);
        assert!(matches!(
            read_validated(image.as_slice(), 0, BTREE_CSUM_XOR),
            Err(Error::WrongLocation {
                block: 0,
                claimed: 7
            })
        ));
    }

    #[test]
    fn rejects_a_block_of_the_wrong_kind() {
        // Right bytes, wrong structure: the XOR separates the namespaces.
        let image = valid_block(0);
        assert!(matches!(
            read_validated(image.as_slice(), 0, crate::BITMAP_CSUM_XOR),
            Err(Error::BadChecksum { .. })
        ));
    }

    #[test]
    fn rejects_reads_past_the_end() {
        let image = vec![0u8; BLOCK_SIZE];
        assert!(matches!(
            image.as_slice().read_block(1),
            Err(Error::OutOfRange(1))
        ));
        assert!(matches!(
            image.as_slice().read_block(u64::MAX),
            Err(Error::OutOfRange(_))
        ));
    }

    #[test]
    fn a_file_reports_the_same_block_past_the_end_as_memory_does() {
        // Every command reads through this impl, so a divergence here costs
        // the block number in each real diagnostic while leaving the
        // in-memory tests above perfectly happy.
        use std::io::Write as _;
        let mut file = tempfile::tempfile().expect("tempfile");
        file.write_all(&vec![0u8; BLOCK_SIZE]).expect("write");
        assert!(matches!(file.read_block(1), Err(Error::OutOfRange(1))));
        assert!(file.read_block(0).is_ok(), "the block that is there");

        // A block straddling the end has run past it just the same; a short
        // read is not a partial block.
        file.write_all(&vec![0u8; BLOCK_SIZE / 2]).expect("write");
        assert!(matches!(file.read_block(1), Err(Error::OutOfRange(1))));
    }
}
