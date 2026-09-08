// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU64;

/// Bytes per sector, kernel-wide.
pub(crate) const SECTOR: u64 = 512;

/// `sizeof(struct disk_exception)` — `__le64 old_chunk; __le64 new_chunk;`.
pub(crate) const EXCEPTION_LEN: usize = 16;

/// `SnAp` little-endian, `dm-snap-persistent.c` `SNAP_MAGIC`.
const MAGIC: u32 = 0x7041_6e53;

/// `SNAPSHOT_DISK_VERSION`.
const VERSION: u32 = 1;

/// dm requires at least 8 sectors. The kernel's true floor is the logical
/// block size of the origin and COW devices, which is only knowable once
/// those devices are named; 8 sectors satisfies a 4 KiB-logical device, the
/// largest block size in common use.
const MIN_SECTORS: u32 = 8;

/// `INT_MAX >> SECTOR_SHIFT` (`dm_exception_store_set_chunk_size`). With the
/// power-of-two rule this makes 2^21 sectors, 1 GiB, the largest usable chunk.
const MAX_SECTORS: u32 = (i32::MAX as u32) >> 9;

/// A validated dm-snapshot chunk size.
///
/// Every size dm accepts is representable, and every one of them has a
/// [`Layer`](crate::Layer): the powers of two from 4 KiB through 1 GiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkSize(u32);

impl ChunkSize {
    /// 32 sectors, 16 KiB — `DM_CHUNK_SIZE_DEFAULT_SECTORS`.
    pub const DEFAULT: Self = Self(32);

    /// The number of leading bytes of a COW that encode its header.
    pub const HEADER_LEN: usize = 16;

    /// Validates a chunk size given in 512-byte sectors.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the size is zero, not a
    /// power of two, below 8 sectors, or above `INT_MAX >> SECTOR_SHIFT`.
    pub fn from_sectors(sectors: u32) -> io::Result<Self> {
        if sectors == 0 || !sectors.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size must be a nonzero power of two",
            ));
        }
        if !(MIN_SECTORS..=MAX_SECTORS).contains(&sectors) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size is outside the range dm accepts",
            ));
        }
        Ok(Self(sectors))
    }

    /// Reads the chunk size out of a COW's header.
    ///
    /// The header is the first [`HEADER_LEN`](Self::HEADER_LEN) bytes of the
    /// COW. Its remaining fields carry no choice: a store this returns for is
    /// valid and version 1.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] if the signature is absent, the
    /// store is marked invalid, the version is unsupported, or the recorded
    /// chunk size is unusable.
    pub fn from_header(header: &[u8; Self::HEADER_LEN]) -> io::Result<Self> {
        let word = |offset: usize| {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&header[offset..offset + 4]);
            u32::from_le_bytes(bytes)
        };

        if word(0) != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a dm-snapshot persistent COW",
            ));
        }
        if word(4) != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot is marked invalid",
            ));
        }
        if word(8) != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported snapshot disk version",
            ));
        }

        Self::from_sectors(word(12))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Returns the chunk size in 512-byte sectors, as a dm table records it.
    #[must_use]
    pub const fn sectors(self) -> u32 {
        self.0
    }

    /// Returns the chunk size in bytes.
    #[must_use]
    pub const fn bytes(self) -> NonZeroU64 {
        match NonZeroU64::new(self.0 as u64 * SECTOR) {
            Some(bytes) => bytes,
            // `from_sectors` rejects zero, so the product is nonzero.
            None => NonZeroU64::MIN,
        }
    }

    /// Returns the number of chunks a COW needs to hold `origin_chunks`
    /// exceptions, including its header, metadata areas, and the trailing
    /// area that terminates the exception list.
    ///
    /// A COW must be this long before a [`Layer`](crate::Layer) is created
    /// over it.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the layout does not fit in
    /// `u64`.
    pub fn cow_chunks(self, origin_chunks: u64) -> io::Result<u64> {
        let overflow =
            || io::Error::new(io::ErrorKind::InvalidInput, "snapshot layout overflows u64");

        let per_area = self.exceptions_per_area();
        let areas = origin_chunks.div_ceil(per_area).max(1);

        // One header chunk, one metadata chunk per area, one data chunk per
        // exception. An exactly-filled last area needs the next area's
        // metadata chunk present as the zero sentinel.
        let mut total = 1u64
            .checked_add(areas)
            .and_then(|total| total.checked_add(origin_chunks))
            .ok_or_else(overflow)?;
        if origin_chunks > 0 && origin_chunks % per_area == 0 {
            total = total.checked_add(1).ok_or_else(overflow)?;
        }
        Ok(total)
    }

    /// The number of `disk_exception` entries one metadata chunk holds.
    pub(crate) const fn exceptions_per_area(self) -> u64 {
        self.bytes().get() / EXCEPTION_LEN as u64
    }

    /// Encodes the 16-byte header for a store with this chunk size.
    pub(crate) fn header(self) -> [u8; Self::HEADER_LEN] {
        let mut header = [0; Self::HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..8].copy_from_slice(&1u32.to_le_bytes());
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&self.0.to_le_bytes());
        header
    }
}
