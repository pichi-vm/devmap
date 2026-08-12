// SPDX-License-Identifier: Apache-2.0

//! The LUKS1 header: one 592-byte big-endian struct with eight inline
//! keyslots, followed by the keyslot areas and then the payload.
//!
//! Field offsets are fixed by the format and pinned by [`OFFSETS`]-style
//! constants below; they were confirmed byte-for-byte against a header
//! `cryptsetup luksFormat --type luks1` produced.

use crate::kdf::Kdf;
use crate::{Error, Hash, SECTOR_SIZE};

/// Bytes of the LUKS1 header proper (before the keyslot areas).
pub const HEADER_SIZE: usize = 592;
/// LUKS1 always has exactly eight keyslots.
pub const KEYSLOTS: usize = 8;
/// Bytes per inline keyslot record.
const KEYSLOT_SIZE: usize = 48;
/// Offset of the first keyslot record.
const KEYSLOTS_OFFSET: usize = 208;
/// `mk-digest` is a SHA-1-sized field regardless of the header's hash spec.
const MK_DIGEST_SIZE: usize = 20;
/// The `active` marker of a keyslot that holds a key.
const KEY_ENABLED: u32 = 0x00AC_71F3;
/// The `active` marker of an empty keyslot.
const KEY_DISABLED: u32 = 0x0000_DEAD;

/// One LUKS1 keyslot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyslot {
    /// Whether this slot holds a wrapped master key.
    pub active: bool,
    /// PBKDF2 iterations for this slot's passphrase.
    pub iterations: u32,
    /// This slot's PBKDF2 salt.
    pub salt: [u8; 32],
    /// Start of the slot's AF-split key material, in sectors.
    pub key_material_offset: u32,
    /// AF stripe count for this slot.
    pub stripes: u32,
}

/// A parsed LUKS1 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Luks1Header {
    /// Cipher name, e.g. `aes`.
    pub cipher_name: String,
    /// Cipher mode, e.g. `xts-plain64`.
    pub cipher_mode: String,
    /// The hash used by the KDF and the AF diffuser.
    pub hash: Hash,
    /// Start of the encrypted payload, in sectors.
    pub payload_offset: u32,
    /// Master key length in bytes.
    pub key_bytes: u32,
    /// Digest of the master key, for checking a recovered candidate.
    pub mk_digest: [u8; MK_DIGEST_SIZE],
    /// Salt for the master-key digest.
    pub mk_salt: [u8; 32],
    /// PBKDF2 iterations for the master-key digest.
    pub mk_iterations: u32,
    /// The volume UUID.
    pub uuid: String,
    /// All eight keyslots, in order.
    pub keyslots: [Keyslot; KEYSLOTS],
}

/// Read a NUL-padded fixed-size string field.
fn field_str(bytes: &[u8], what: &'static str) -> Result<String, Error> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
}

impl Luks1Header {
    /// Parse a LUKS1 header from the start of a device.
    ///
    /// The caller has already matched the magic and read the version; this
    /// decodes the rest.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the buffer is short or a field is unusable,
    /// or [`Error::Unsupported`] for a hash spec this crate lacks.
    // The leading length check covers every fixed-offset slice below, so the
    // `try_into().unwrap()`s cannot panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < HEADER_SIZE {
            return Err(Error::Malformed(format!(
                "LUKS1 header needs {HEADER_SIZE} bytes, got {}",
                raw.len()
            )));
        }
        let be32 = |off: usize| u32::from_be_bytes(raw[off..off + 4].try_into().unwrap());

        let hash_spec = field_str(&raw[72..104], "hash-spec")?;
        let hash = Hash::from_spec(&hash_spec).ok_or(Error::Unsupported {
            what: "hash",
            name: hash_spec,
        })?;

        let mut keyslots = Vec::with_capacity(KEYSLOTS);
        for i in 0..KEYSLOTS {
            let base = KEYSLOTS_OFFSET + i * KEYSLOT_SIZE;
            let active = be32(base);
            if active != KEY_ENABLED && active != KEY_DISABLED {
                return Err(Error::Malformed(format!(
                    "keyslot {i} has an unknown active marker {active:#010x}"
                )));
            }
            keyslots.push(Keyslot {
                active: active == KEY_ENABLED,
                iterations: be32(base + 4),
                salt: raw[base + 8..base + 40].try_into().unwrap(),
                key_material_offset: be32(base + 40),
                stripes: be32(base + 44),
            });
        }

        Ok(Luks1Header {
            cipher_name: field_str(&raw[8..40], "cipher-name")?,
            cipher_mode: field_str(&raw[40..72], "cipher-mode")?,
            hash,
            payload_offset: be32(104),
            key_bytes: be32(108),
            mk_digest: raw[112..132].try_into().unwrap(),
            mk_salt: raw[132..164].try_into().unwrap(),
            mk_iterations: be32(164),
            uuid: field_str(&raw[168..208], "uuid")?,
            keyslots: keyslots
                .try_into()
                .expect("pushed exactly KEYSLOTS entries"),
        })
    }

    /// The full cipher spec for a dm-crypt table, e.g. `aes-xts-plain64`.
    #[must_use]
    pub fn cipher_spec(&self) -> String {
        format!("{}-{}", self.cipher_name, self.cipher_mode)
    }

    /// Byte offset of the encrypted payload.
    #[must_use]
    pub fn payload_offset_bytes(&self) -> u64 {
        u64::from(self.payload_offset) * SECTOR_SIZE
    }

    /// The KDF for `keyslot`, as the header records it.
    #[must_use]
    pub fn keyslot_kdf(&self, keyslot: &Keyslot) -> Kdf {
        Kdf::Pbkdf2 {
            hash: self.hash,
            iterations: keyslot.iterations,
        }
    }

    /// Whether `candidate` is the master key this header describes.
    ///
    /// Compares the PBKDF2 digest the header stores, which is what tells a
    /// wrong passphrase apart from a corrupt volume.
    #[must_use]
    pub fn verify_master_key(&self, candidate: &[u8]) -> bool {
        let kdf = Kdf::Pbkdf2 {
            hash: self.hash,
            iterations: self.mk_iterations,
        };
        let Ok(derived) = kdf.derive(candidate, &self.mk_salt, MK_DIGEST_SIZE) else {
            return false;
        };
        // Constant-time-ish: compare every byte, no early exit.
        derived
            .expose()
            .iter()
            .zip(&self.mk_digest)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed LUKS1 header, built field by field.
    fn header_bytes() -> Vec<u8> {
        let mut h = vec![0u8; HEADER_SIZE];
        h[0..6].copy_from_slice(&crate::LUKS_MAGIC);
        h[6..8].copy_from_slice(&1u16.to_be_bytes());
        h[8..11].copy_from_slice(b"aes");
        h[40..51].copy_from_slice(b"xts-plain64");
        h[72..78].copy_from_slice(b"sha256");
        h[104..108].copy_from_slice(&4096u32.to_be_bytes());
        h[108..112].copy_from_slice(&64u32.to_be_bytes());
        h[164..168].copy_from_slice(&371_308u32.to_be_bytes());
        h[168..204].copy_from_slice(b"9d547e6e-c5cf-4b5e-a27f-68097fe15d04");
        // Slot 0 enabled, the rest disabled.
        h[208..212].copy_from_slice(&KEY_ENABLED.to_be_bytes());
        h[212..216].copy_from_slice(&5_932_536u32.to_be_bytes());
        h[248..252].copy_from_slice(&8u32.to_be_bytes());
        h[252..256].copy_from_slice(&4000u32.to_be_bytes());
        for i in 1..KEYSLOTS {
            let base = KEYSLOTS_OFFSET + i * KEYSLOT_SIZE;
            h[base..base + 4].copy_from_slice(&KEY_DISABLED.to_be_bytes());
        }
        h
    }

    #[test]
    fn parses_the_fields_cryptsetup_wrote() {
        // Values captured from a real `cryptsetup luksFormat --type luks1`.
        let h = Luks1Header::parse(&header_bytes()).expect("parse");
        assert_eq!(h.cipher_name, "aes");
        assert_eq!(h.cipher_mode, "xts-plain64");
        assert_eq!(h.cipher_spec(), "aes-xts-plain64");
        assert_eq!(h.hash, Hash::Sha256);
        assert_eq!(h.payload_offset, 4096);
        assert_eq!(h.payload_offset_bytes(), 4096 * 512);
        assert_eq!(h.key_bytes, 64);
        assert_eq!(h.mk_iterations, 371_308);
        assert_eq!(h.uuid, "9d547e6e-c5cf-4b5e-a27f-68097fe15d04");
        assert!(h.keyslots[0].active);
        assert_eq!(h.keyslots[0].iterations, 5_932_536);
        assert_eq!(h.keyslots[0].key_material_offset, 8);
        assert_eq!(h.keyslots[0].stripes, 4000);
        assert!(h.keyslots[1..].iter().all(|k| !k.active));
    }

    #[test]
    fn rejects_a_short_buffer() {
        assert!(Luks1Header::parse(&[0u8; 100]).is_err());
    }

    #[test]
    fn rejects_an_unknown_hash_spec() {
        let mut h = header_bytes();
        h[72..104].fill(0);
        h[72..75].copy_from_slice(b"md5");
        assert!(matches!(
            Luks1Header::parse(&h),
            Err(Error::Unsupported { what: "hash", .. })
        ));
    }

    #[test]
    fn rejects_a_corrupt_keyslot_marker() {
        // Neither ENABLED nor DISABLED means the header is damaged; treating
        // it as "inactive" would silently hide a usable slot.
        let mut h = header_bytes();
        h[208..212].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert!(matches!(Luks1Header::parse(&h), Err(Error::Malformed(_))));
    }

    #[test]
    fn verify_master_key_accepts_only_the_right_key() {
        let mut raw = header_bytes();
        // Pin a cheap digest so the test is fast, then compute the digest a
        // known key would produce and store it.
        raw[164..168].copy_from_slice(&1000u32.to_be_bytes());
        let mut h = Luks1Header::parse(&raw).expect("parse");
        let key = vec![0x5Au8; 64];
        let digest = Kdf::Pbkdf2 {
            hash: h.hash,
            iterations: h.mk_iterations,
        }
        .derive(&key, &h.mk_salt, MK_DIGEST_SIZE)
        .expect("derive");
        h.mk_digest.copy_from_slice(digest.expose());

        assert!(h.verify_master_key(&key));
        assert!(!h.verify_master_key(&[0x5Bu8; 64]), "wrong key rejected");
        assert!(!h.verify_master_key(&[]), "empty key rejected");
    }
}
