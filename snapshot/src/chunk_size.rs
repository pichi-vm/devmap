// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU32;

/// A validated dm-snapshot chunk size.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChunkSize {
    sectors: NonZeroU32,
    len: usize,
}

impl ChunkSize {
    const SECTOR_BYTES: u64 = 512;
    const MAX_SECTORS: u32 = (i32::MAX as u32) >> 9;

    pub(crate) fn new(sectors: NonZeroU32) -> io::Result<Self> {
        if !sectors.get().is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size must be a nonzero power of two",
            ));
        }
        if sectors.get() > Self::MAX_SECTORS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size is outside the range dm accepts",
            ));
        }

        let bytes = u64::from(sectors.get()) * Self::SECTOR_BYTES;
        let len = usize::try_from(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "chunk size exceeds usize"))?;
        Ok(Self { sectors, len })
    }

    pub(crate) const fn sectors(self) -> NonZeroU32 {
        self.sectors
    }

    pub(crate) const fn bytes(self) -> u64 {
        self.sectors.get() as u64 * Self::SECTOR_BYTES
    }

    pub(crate) const fn len(self) -> usize {
        self.len
    }

    pub(crate) fn offset(self, index: u64) -> io::Result<u64> {
        index
            .checked_mul(self.bytes())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "snapshot offset overflows"))
    }
}

/// The unverified on-disk snapshot header.
#[derive(Default)]
pub(crate) struct Header([u8; Self::LEN]);

impl Header {
    pub(crate) const LEN: usize = 16;
    const MAGIC: u32 = 0x7041_6e53;
    const VALID: u32 = 1;
    const VERSION: u32 = 1;

    pub(crate) fn new(chunk_size: ChunkSize) -> Self {
        let mut bytes = [0; Self::LEN];
        bytes[0..4].copy_from_slice(&Self::MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&Self::VALID.to_le_bytes());
        bytes[8..12].copy_from_slice(&Self::VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&chunk_size.sectors().get().to_le_bytes());
        Self(bytes)
    }

    pub(crate) fn chunk_size(&self) -> io::Result<ChunkSize> {
        let word = |offset: usize| {
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&self.0[offset..offset + 4]);
            u32::from_le_bytes(bytes)
        };

        if word(0) != Self::MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a dm-snapshot persistent COW",
            ));
        }
        if word(4) != Self::VALID {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot is marked invalid",
            ));
        }
        if word(8) != Self::VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported snapshot disk version",
            ));
        }

        let sectors = NonZeroU32::new(word(12)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk size must be a nonzero power of two",
            )
        })?;
        ChunkSize::new(sectors).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl AsRef<[u8]> for Header {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Header {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
