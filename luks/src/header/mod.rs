// SPDX-License-Identifier: Apache-2.0

//! Reading a LUKS header, either version.
//!
//! Both versions start with the same six magic bytes and a big-endian `u16`
//! version, so detection is: match the magic, read the version, dispatch.

pub mod json;
pub mod luks1;
pub mod luks2;

pub use luks1::Luks1Header;
pub use luks2::Luks2Header;

use crate::{Error, LUKS_MAGIC};

/// Bytes that must be read to identify a header of either version. LUKS1's
/// header is 592 bytes and LUKS2's binary header is 4096; reading 4096
/// covers both.
pub const DETECT_SIZE: usize = 4096;

/// A LUKS header of either version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Header {
    /// A LUKS1 volume.
    V1(Box<Luks1Header>),
    /// A LUKS2 volume.
    V2(Box<Luks2Header>),
}

impl Header {
    /// Identify and parse the header at the start of `raw`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMagic`] if `raw` is not a LUKS volume,
    /// [`Error::BadVersion`] for a version this crate does not implement,
    /// or a parse error from the version-specific decoder.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 8 || raw[..6] != LUKS_MAGIC {
            return Err(Error::BadMagic);
        }
        match u16::from_be_bytes([raw[6], raw[7]]) {
            1 => Ok(Header::V1(Box::new(Luks1Header::parse(raw)?))),
            2 => Ok(Header::V2(Box::new(Luks2Header::parse(raw)?))),
            other => Err(Error::BadVersion(other)),
        }
    }

    /// The volume UUID.
    #[must_use]
    pub fn uuid(&self) -> &str {
        match self {
            Header::V1(h) => &h.uuid,
            Header::V2(h) => &h.uuid,
        }
    }

    /// The cipher spec for a dm-crypt table, e.g. `aes-xts-plain64`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a LUKS2 volume declares no data segment.
    pub fn cipher_spec(&self) -> Result<String, Error> {
        match self {
            Header::V1(h) => Ok(h.cipher_spec()),
            Header::V2(h) => h.cipher_spec(),
        }
    }

    /// Byte offset of the encrypted payload within the device.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a LUKS2 volume declares no data segment.
    pub fn payload_offset_bytes(&self) -> Result<u64, Error> {
        match self {
            Header::V1(h) => Ok(h.payload_offset_bytes()),
            Header::V2(h) => h.payload_offset_bytes(),
        }
    }

    /// Master key length in bytes.
    #[must_use]
    pub fn key_bytes(&self) -> u32 {
        match self {
            Header::V1(h) => h.key_bytes,
            Header::V2(h) => h.key_bytes(),
        }
    }

    /// The encryption unit in bytes: always a 512-byte sector for LUKS1,
    /// configurable (commonly 4096) for LUKS2.
    #[must_use]
    pub fn sector_size(&self) -> u32 {
        match self {
            Header::V1(_) => 512,
            Header::V2(h) => h
                .metadata
                .first_segment()
                .map_or(512, |segment| segment.sector_size),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_non_luks_device() {
        assert!(matches!(Header::parse(&[0u8; 4096]), Err(Error::BadMagic)));
        assert!(matches!(Header::parse(b"LUK"), Err(Error::BadMagic)));
    }

    #[test]
    fn reports_an_unimplemented_version() {
        let mut raw = vec![0u8; DETECT_SIZE];
        raw[..6].copy_from_slice(&LUKS_MAGIC);
        raw[6..8].copy_from_slice(&9u16.to_be_bytes());
        assert!(matches!(Header::parse(&raw), Err(Error::BadVersion(9))));
    }
}
