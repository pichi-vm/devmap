// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

/// Capacity recorded in a recognized dm-integrity superblock.
///
/// Reads the fixed header prefix. It does not check the journal, tags, or
/// data contents. Versions 1 through 7 share the capacity field's layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    version: u8,
    data_sectors: u64,
}

impl Header {
    /// Reads the superblock prefix at byte zero.
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEof` for a short record, `InvalidData` for an
    /// unknown magic or version, or the underlying I/O error.
    pub fn open(mut storage: impl Read + Seek) -> io::Result<Self> {
        storage.seek(SeekFrom::Start(0))?;
        let mut bytes = [0; 24];
        storage.read_exact(&mut bytes)?;
        if &bytes[..8] != b"integrt\0" || !(1..=7).contains(&bytes[8]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported dm-integrity superblock",
            ));
        }
        let mut count = [0; 8];
        count.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            version: bytes[8],
            data_sectors: u64::from_le_bytes(count),
        })
    }
    /// Returns the on-disk version.
    pub const fn version(self) -> u8 {
        self.version
    }
    /// Returns the usable capacity in 512-byte sectors.
    pub const fn data_sectors(self) -> u64 {
        self.data_sectors
    }
}
