// SPDX-License-Identifier: Apache-2.0

//! The LUKS2 JSON metadata area.
//!
//! LUKS2 keeps everything but the binary header in JSON: the keyslots, the
//! digests that validate a recovered master key, the segments describing
//! how the data is encrypted, and volume config.
//!
//! One quirk drives most of the types here: **byte offsets and sizes are
//! encoded as JSON strings**, not numbers (`"offset":"16777216"`), because
//! they can exceed what a JSON number is guaranteed to represent. Salts and
//! digests are base64.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::Deserialize;

use crate::Error;

/// Deserialize a decimal integer that LUKS2 encodes as a JSON string.
fn de_string_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

/// Decode a base64 field into bytes.
fn de_base64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(serde::de::Error::custom)
}

/// The whole LUKS2 metadata document.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    /// Keyslots by index, each wrapping the master key under one passphrase.
    pub keyslots: BTreeMap<String, Keyslot>,
    /// Digests by index, used to check a recovered master key.
    pub digests: BTreeMap<String, Digest>,
    /// Data segments by index — how and where the payload is encrypted.
    pub segments: BTreeMap<String, Segment>,
}

/// One LUKS2 keyslot.
#[derive(Debug, Clone, Deserialize)]
pub struct Keyslot {
    /// Slot type; this crate implements `luks2`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Length of the key this slot stores, in bytes.
    pub key_size: usize,
    /// Anti-forensic split parameters.
    pub af: Af,
    /// Where and how the split key material is stored.
    pub area: Area,
    /// How to derive this slot's key from a passphrase.
    pub kdf: KdfSpec,
}

/// Anti-forensic split parameters for a keyslot.
#[derive(Debug, Clone, Deserialize)]
pub struct Af {
    /// AF flavour; `luks1` is the only one defined.
    #[serde(rename = "type")]
    pub kind: String,
    /// Number of stripes the key is expanded into.
    pub stripes: usize,
    /// Hash used by the AF diffuser.
    pub hash: String,
}

/// Where a keyslot's split key material lives, and how it is encrypted.
#[derive(Debug, Clone, Deserialize)]
pub struct Area {
    /// Area type; `raw` is the only one this crate reads.
    #[serde(rename = "type")]
    pub kind: String,
    /// Byte offset of the area within the device.
    #[serde(deserialize_with = "de_string_u64")]
    pub offset: u64,
    /// Byte length of the area.
    #[serde(deserialize_with = "de_string_u64")]
    pub size: u64,
    /// Cipher spec the area is encrypted with, e.g. `aes-xts-plain64`.
    pub encryption: String,
    /// Length of the key that decrypts the area.
    pub key_size: usize,
}

/// A keyslot's key-derivation parameters.
///
/// The fields present depend on `type`: argon2 slots carry time/memory/cpus,
/// PBKDF2 slots carry hash/iterations.
#[derive(Debug, Clone, Deserialize)]
pub struct KdfSpec {
    /// `argon2i`, `argon2id`, or `pbkdf2`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The KDF salt.
    #[serde(deserialize_with = "de_base64")]
    pub salt: Vec<u8>,
    /// argon2 passes over memory.
    #[serde(default)]
    pub time: u32,
    /// argon2 memory cost in KiB.
    #[serde(default)]
    pub memory: u32,
    /// argon2 parallelism.
    #[serde(default)]
    pub cpus: u32,
    /// PBKDF2 hash.
    #[serde(default)]
    pub hash: Option<String>,
    /// PBKDF2 iteration count.
    #[serde(default)]
    pub iterations: u32,
}

/// A digest that validates a recovered master key.
#[derive(Debug, Clone, Deserialize)]
pub struct Digest {
    /// Digest type; `pbkdf2` is what cryptsetup writes.
    #[serde(rename = "type")]
    pub kind: String,
    /// Which keyslots this digest covers.
    pub keyslots: Vec<String>,
    /// The PBKDF2 hash.
    pub hash: String,
    /// The PBKDF2 iteration count.
    pub iterations: u32,
    /// The PBKDF2 salt.
    #[serde(deserialize_with = "de_base64")]
    pub salt: Vec<u8>,
    /// The expected digest of the master key.
    #[serde(deserialize_with = "de_base64")]
    pub digest: Vec<u8>,
}

/// A data segment: the encrypted payload's geometry.
#[derive(Debug, Clone, Deserialize)]
pub struct Segment {
    /// Segment type; `crypt` for an encrypted payload.
    #[serde(rename = "type")]
    pub kind: String,
    /// Byte offset of the payload within the device.
    #[serde(deserialize_with = "de_string_u64")]
    pub offset: u64,
    /// Cipher spec for the payload, e.g. `aes-xts-plain64`.
    pub encryption: String,
    /// The encryption unit in bytes.
    pub sector_size: u32,
    /// IV offset applied to the segment, as a decimal string.
    #[serde(default, rename = "iv_tweak", deserialize_with = "de_string_u64")]
    pub iv_tweak: u64,
}

impl Metadata {
    /// Parse the JSON area, which is NUL-padded out to its allotted size.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] if the document does not match the LUKS2 schema.
    pub fn parse(json_area: &[u8]) -> Result<Self, Error> {
        let end = json_area
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(json_area.len());
        Ok(serde_json::from_slice(&json_area[..end])?)
    }

    /// The digest covering `keyslot`, if any.
    #[must_use]
    pub fn digest_for(&self, keyslot: &str) -> Option<&Digest> {
        self.digests
            .values()
            .find(|d| d.keyslots.iter().any(|k| k == keyslot))
    }

    /// The first data segment, which is the payload for a plain volume.
    #[must_use]
    pub fn first_segment(&self) -> Option<&Segment> {
        self.segments.values().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON area of a volume `cryptsetup luksFormat --type luks2`
    /// produced, captured verbatim.
    const REAL: &str = r#"{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"argon2id","time":4,"memory":32,"cpus":1,"salt":"ZHj0Lf3N8PXN7jpK0HjiRAG0rCOFGnVg2ueCVJhD94k="}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"7o6i/Pf2lmJmvejxrH5floRMMG/SfFRpq01BlC+4mIk=","digest":"IbMrLmzX3aee4Ie/OCZRHU7jhlK7vP8cOmaxJw6B3ws="}},"config":{"json_size":"12288","keyslots_size":"16744448"}}"#;

    #[test]
    fn parses_metadata_cryptsetup_wrote() {
        let md = Metadata::parse(REAL.as_bytes()).expect("parse");

        let slot = &md.keyslots["0"];
        assert_eq!(slot.kind, "luks2");
        assert_eq!(slot.key_size, 64);
        assert_eq!(slot.af.stripes, 4000);
        assert_eq!(slot.af.hash, "sha256");
        // The string-encoded integers are the quirk worth pinning.
        assert_eq!(slot.area.offset, 32768);
        assert_eq!(slot.area.size, 258_048);
        assert_eq!(slot.area.encryption, "aes-xts-plain64");
        assert_eq!(slot.kdf.kind, "argon2id");
        assert_eq!((slot.kdf.time, slot.kdf.memory, slot.kdf.cpus), (4, 32, 1));
        assert_eq!(slot.kdf.salt.len(), 32, "base64 salt decodes to 32 bytes");

        let digest = md.digest_for("0").expect("digest covers slot 0");
        assert_eq!(digest.kind, "pbkdf2");
        assert_eq!(digest.iterations, 1000);
        assert_eq!(digest.digest.len(), 32);

        let segment = md.first_segment().expect("a segment");
        assert_eq!(segment.offset, 16_777_216);
        assert_eq!(segment.sector_size, 4096);
        assert_eq!(segment.encryption, "aes-xts-plain64");
    }

    #[test]
    fn tolerates_the_nul_padding_of_the_json_area() {
        // The area is a fixed size; the document is NUL-padded to fill it.
        let mut padded = REAL.as_bytes().to_vec();
        padded.resize(12288, 0);
        assert!(Metadata::parse(&padded).is_ok());
    }

    #[test]
    fn rejects_malformed_metadata() {
        assert!(Metadata::parse(b"{").is_err());
        assert!(Metadata::parse(b"{}").is_err(), "missing required sections");
        // An offset that is not a decimal string must not silently become 0.
        let bad = REAL.replace(r#""offset":"32768""#, r#""offset":"not-a-number""#);
        assert!(Metadata::parse(bad.as_bytes()).is_err());
    }
}
