// SPDX-License-Identifier: Apache-2.0

//! Reading a LUKS header, either version.
//!
//! Both versions start with the same six magic bytes and a big-endian `u16`
//! version, so detection is: match the magic, read the version, dispatch.

pub mod luks1;

pub use luks1::Luks1Header;

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
    V1(Luks1Header),
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
            1 => Ok(Header::V1(Luks1Header::parse(raw)?)),
            other => Err(Error::BadVersion(other)),
        }
    }

    /// The volume UUID.
    #[must_use]
    pub fn uuid(&self) -> &str {
        match self {
            Header::V1(h) => &h.uuid,
        }
    }

    /// The cipher spec for a dm-crypt table, e.g. `aes-xts-plain64`.
    #[must_use]
    pub fn cipher_spec(&self) -> String {
        match self {
            Header::V1(h) => h.cipher_spec(),
        }
    }

    /// Byte offset of the encrypted payload within the device.
    #[must_use]
    pub fn payload_offset_bytes(&self) -> u64 {
        match self {
            Header::V1(h) => h.payload_offset_bytes(),
        }
    }

    /// Master key length in bytes.
    #[must_use]
    pub fn key_bytes(&self) -> u32 {
        match self {
            Header::V1(h) => h.key_bytes,
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
