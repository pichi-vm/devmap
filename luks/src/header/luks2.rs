// SPDX-License-Identifier: Apache-2.0

//! The LUKS2 header: a 4096-byte big-endian binary header followed by a
//! JSON metadata area, written twice — a primary copy at offset 0 and a
//! secondary copy at `hdr_size` — so a torn update can be recovered from
//! the other.
//!
//! Field offsets were confirmed byte-for-byte against a header
//! `cryptsetup luksFormat --type luks2` produced.

use super::json::Metadata;
use crate::{Error, Hash, LUKS_MAGIC, LUKS2_SECONDARY_MAGIC};

/// Size of the binary header, before the JSON area.
pub const BINARY_HEADER_SIZE: usize = 4096;

// Field offsets within the binary header.
const OFF_VERSION: usize = 6;
const OFF_HDR_SIZE: usize = 8;
const OFF_SEQID: usize = 16;
const OFF_LABEL: usize = 24;
const OFF_CHECKSUM_ALG: usize = 72;
// The header salt at offset 104 is not consulted when reading: LUKS2
// keyslots carry their own salts in the JSON metadata.
const OFF_UUID: usize = 168;
const OFF_SUBSYSTEM: usize = 208;
const OFF_CSUM: usize = 448;
/// The checksum field is sized for the largest supported digest.
const CSUM_FIELD_SIZE: usize = 64;

/// A parsed LUKS2 header: the binary part plus its JSON metadata.
#[derive(Debug, Clone)]
pub struct Luks2Header {
    /// Total size of the header (binary + JSON area) in bytes.
    pub hdr_size: u64,
    /// Update counter; the copy with the higher value is the current one.
    pub seqid: u64,
    /// Optional volume label.
    pub label: String,
    /// Optional subsystem label.
    pub subsystem: String,
    /// The volume UUID.
    pub uuid: String,
    /// The JSON metadata.
    pub metadata: Metadata,
}

// PartialEq compares the identity-bearing fields; Metadata is serde-derived
// and not comparable, but a matching uuid and seqid identify a header.
impl PartialEq for Luks2Header {
    fn eq(&self, other: &Self) -> bool {
        self.hdr_size == other.hdr_size
            && self.seqid == other.seqid
            && self.uuid == other.uuid
            && self.label == other.label
            && self.subsystem == other.subsystem
    }
}
impl Eq for Luks2Header {}

/// Read a NUL-padded fixed-size string field.
fn field_str(bytes: &[u8], what: &'static str) -> Result<String, Error> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
}

/// Verify a header copy's checksum: the digest is taken over the whole
/// header (binary + JSON area) with the checksum field zeroed.
fn checksum_matches(header: &[u8], hash: Hash, stored: &[u8]) -> bool {
    let mut scratch = header.to_vec();
    scratch[OFF_CSUM..OFF_CSUM + CSUM_FIELD_SIZE].fill(0);
    let computed = hash.digest(&scratch);
    computed.len() <= stored.len() && computed == stored[..computed.len()]
}

impl Luks2Header {
    /// Parse one header copy starting at `raw[0]`, verifying its checksum.
    ///
    /// `raw` must hold the whole copy: the binary header and its JSON area.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a short buffer or unusable field,
    /// [`Error::BadChecksum`] if the copy is corrupt, [`Error::Unsupported`]
    /// for an unknown checksum algorithm, or [`Error::Json`] from the
    /// metadata.
    // The leading length checks cover every fixed-offset slice below.
    #[allow(clippy::missing_panics_doc)]
    pub fn parse_copy(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < BINARY_HEADER_SIZE {
            return Err(Error::Malformed(format!(
                "LUKS2 header needs {BINARY_HEADER_SIZE} bytes, got {}",
                raw.len()
            )));
        }
        let hdr_size = u64::from_be_bytes(raw[OFF_HDR_SIZE..OFF_HDR_SIZE + 8].try_into().unwrap());
        let total = usize::try_from(hdr_size)
            .map_err(|_| Error::Malformed("hdr_size out of range".to_owned()))?;
        if total < BINARY_HEADER_SIZE || raw.len() < total {
            return Err(Error::Malformed(format!(
                "hdr_size {hdr_size} does not fit the {} bytes available",
                raw.len()
            )));
        }

        let alg = field_str(
            &raw[OFF_CHECKSUM_ALG..OFF_CHECKSUM_ALG + 32],
            "checksum_alg",
        )?;
        let hash = Hash::from_spec(&alg).ok_or(Error::Unsupported {
            what: "header checksum",
            name: alg,
        })?;
        if !checksum_matches(
            &raw[..total],
            hash,
            &raw[OFF_CSUM..OFF_CSUM + CSUM_FIELD_SIZE],
        ) {
            return Err(Error::BadChecksum);
        }

        Ok(Luks2Header {
            hdr_size,
            seqid: u64::from_be_bytes(raw[OFF_SEQID..OFF_SEQID + 8].try_into().unwrap()),
            label: field_str(&raw[OFF_LABEL..OFF_LABEL + 48], "label")?,
            subsystem: field_str(&raw[OFF_SUBSYSTEM..OFF_SUBSYSTEM + 48], "subsystem")?,
            uuid: field_str(&raw[OFF_UUID..OFF_UUID + 40], "uuid")?,
            metadata: Metadata::parse(&raw[BINARY_HEADER_SIZE..total])?,
        })
    }

    /// Parse a LUKS2 volume, preferring whichever header copy is current.
    ///
    /// The primary copy sits at offset 0 and the secondary at `hdr_size`.
    /// If both are readable the one with the higher `seqid` wins; if the
    /// primary is corrupt the secondary is used, which is the recovery the
    /// two copies exist for.
    ///
    /// # Errors
    ///
    /// The primary copy's error if neither copy can be read.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let primary = Self::parse_copy(raw);

        // The secondary lives at hdr_size, which the primary records — and
        // which is still readable from a primary whose checksum failed.
        let secondary = raw
            .get(OFF_HDR_SIZE..OFF_HDR_SIZE + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .and_then(|hdr_size| usize::try_from(hdr_size).ok())
            .filter(|&off| off >= BINARY_HEADER_SIZE)
            .and_then(|off| raw.get(off..))
            .filter(|tail| tail.len() >= BINARY_HEADER_SIZE && tail[..6] == LUKS2_SECONDARY_MAGIC)
            .map(Self::parse_copy);

        match (primary, secondary) {
            (Ok(p), Some(Ok(s))) => Ok(if s.seqid > p.seqid { s } else { p }),
            (Ok(p), _) => Ok(p),
            (Err(_), Some(Ok(s))) => Ok(s),
            (Err(e), _) => Err(e),
        }
    }

    /// The cipher spec for a dm-crypt table, from the first data segment.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the volume declares no segment.
    pub fn cipher_spec(&self) -> Result<String, Error> {
        self.metadata
            .first_segment()
            .map(|s| s.encryption.clone())
            .ok_or_else(|| Error::Malformed("no data segment".to_owned()))
    }

    /// Byte offset of the encrypted payload.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the volume declares no segment.
    pub fn payload_offset_bytes(&self) -> Result<u64, Error> {
        self.metadata
            .first_segment()
            .map(|s| s.offset)
            .ok_or_else(|| Error::Malformed("no data segment".to_owned()))
    }

    /// Master key length in bytes, taken from the digest's keyslot.
    #[must_use]
    pub fn key_bytes(&self) -> u32 {
        self.metadata
            .keyslots
            .values()
            .next()
            .map_or(0, |slot| u32::try_from(slot.key_size).unwrap_or(0))
    }
}

/// Whether `raw` starts with a LUKS2 primary header magic and version.
#[must_use]
pub fn is_luks2(raw: &[u8]) -> bool {
    raw.len() >= 8
        && raw[..6] == LUKS_MAGIC
        && u16::from_be_bytes([raw[OFF_VERSION], raw[OFF_VERSION + 1]]) == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_short_buffer() {
        assert!(Luks2Header::parse_copy(&[0u8; 100]).is_err());
    }

    #[test]
    fn rejects_an_implausible_hdr_size() {
        let mut raw = vec![0u8; BINARY_HEADER_SIZE];
        raw[..6].copy_from_slice(&LUKS_MAGIC);
        raw[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&2u16.to_be_bytes());
        // Smaller than the binary header itself.
        raw[OFF_HDR_SIZE..OFF_HDR_SIZE + 8].copy_from_slice(&64u64.to_be_bytes());
        assert!(matches!(
            Luks2Header::parse_copy(&raw),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn detects_luks2_by_magic_and_version() {
        let mut raw = vec![0u8; 8];
        raw[..6].copy_from_slice(&LUKS_MAGIC);
        raw[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&2u16.to_be_bytes());
        assert!(is_luks2(&raw));
        raw[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&1u16.to_be_bytes());
        assert!(!is_luks2(&raw), "LUKS1 is not LUKS2");
        assert!(!is_luks2(&[0u8; 8]));
    }
}
