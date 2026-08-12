// SPDX-License-Identifier: Apache-2.0

//! The **LUKS1 and LUKS2 on-disk formats** — a pure-Rust way to read (and
//! create) encrypted volumes and hand them to dm-crypt, with no
//! `cryptsetup`.
//!
//! # What a LUKS volume is
//!
//! The data is encrypted under a **master key** that is never derived from
//! the passphrase. Instead each *keyslot* stores that master key wrapped by
//! a passphrase-derived key, so a volume can have several passphrases and
//! any one can be changed or revoked without re-encrypting the data.
//!
//! Unlocking therefore runs, per keyslot:
//!
//! 1. derive a key from the passphrase with the slot's KDF ([`kdf`]) —
//!    argon2 for LUKS2, PBKDF2 for LUKS1;
//! 2. decrypt the slot's keyslot area with it (AES-XTS by default);
//! 3. [`af`]-merge the result to recover the candidate master key;
//! 4. check that candidate against the header's digest.
//!
//! A wrong passphrase fails at step 4, so the digest is what distinguishes
//! "wrong passphrase" from "corrupt volume".
//!
//! # Key material
//!
//! [`Secret`] zeroizes on drop and redacts in `Debug`. Nothing in this
//! crate prints key bytes; keep it that way.

pub mod af;
pub mod header;
pub mod kdf;
pub mod unlock;

pub use header::{Header, Luks1Header};
pub use unlock::{KeyslotAreas, MasterKey};

use sha1::Digest as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// LUKS's magic, at offset 0 of a primary header of either version.
pub const LUKS_MAGIC: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];
/// The magic of a LUKS2 secondary (backup) header.
pub const LUKS2_SECONDARY_MAGIC: [u8; 6] = [b'S', b'K', b'U', b'L', 0xba, 0xbe];
/// 512 bytes per sector, the unit LUKS records offsets in.
pub const SECTOR_SIZE: u64 = 512;

/// The hash functions LUKS headers name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hash {
    /// SHA-1 — LUKS1's `mk-digest` is 20 bytes, so LUKS1 volumes use it.
    Sha1,
    /// SHA-256, the modern default.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// Parse a header's hash spec (`"sha256"`, `"sha1"`, `"sha512"`).
    #[must_use]
    pub fn from_spec(spec: &str) -> Option<Hash> {
        match spec {
            "sha1" => Some(Hash::Sha1),
            "sha256" => Some(Hash::Sha256),
            "sha512" => Some(Hash::Sha512),
            _ => None,
        }
    }

    /// The name LUKS writes into a header for this hash.
    #[must_use]
    pub fn spec(self) -> &'static str {
        match self {
            Hash::Sha1 => "sha1",
            Hash::Sha256 => "sha256",
            Hash::Sha512 => "sha512",
        }
    }

    /// Digest length in bytes.
    #[must_use]
    pub fn digest_size(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha512 => 64,
        }
    }

    /// Hash `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Hash `big-endian(counter) || data` — the AF diffuser's per-block
    /// construction, which keys each block by its index so that identical
    /// blocks do not diffuse identically.
    #[must_use]
    pub fn digest_with_counter(self, counter: u32, data: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(4 + data.len());
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(data);
        let out = self.digest(&input);
        input.zeroize();
        out
    }
}

/// Why a LUKS volume could not be read or unlocked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The device does not start with a LUKS header.
    #[error("not a LUKS volume (bad magic)")]
    BadMagic,

    /// The header version is neither 1 nor 2.
    #[error("unsupported LUKS version: {0}")]
    BadVersion(u16),

    /// A fixed-size header field held something unusable.
    #[error("malformed LUKS header: {0}")]
    Malformed(String),

    /// The LUKS2 header checksum did not match its contents.
    #[error("LUKS2 header checksum mismatch (header is corrupt)")]
    BadChecksum,

    /// The header names an algorithm this crate does not implement.
    #[error("unsupported {what}: {name}")]
    Unsupported {
        /// What kind of algorithm (cipher, hash, kdf, ...).
        what: &'static str,
        /// The name the header gave.
        name: String,
    },

    /// The LUKS2 JSON metadata did not parse.
    #[error("malformed LUKS2 JSON metadata: {0}")]
    Json(#[from] serde_json::Error),

    /// No keyslot accepted the passphrase.
    #[error("no key available with this passphrase")]
    NoKey,

    /// Reading the device failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Bytes that must not be logged or left in freed memory.
///
/// Zeroizes on drop and redacts in `Debug`, so a stray `{:?}` cannot leak
/// key material.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Take ownership of `bytes` as secret material.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }

    /// The raw bytes. Callers must not log or persist these.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<{} bytes redacted>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_specs_round_trip() {
        for h in [Hash::Sha1, Hash::Sha256, Hash::Sha512] {
            assert_eq!(Hash::from_spec(h.spec()), Some(h));
            assert_eq!(h.digest(b"").len(), h.digest_size());
        }
        assert_eq!(Hash::from_spec("md5"), None);
    }

    #[test]
    fn sha256_matches_a_known_vector() {
        // SHA-256("abc"), the FIPS 180-4 example.
        assert_eq!(
            Hash::Sha256.digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn secret_debug_redacts() {
        let s = Secret::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let shown = format!("{s:?}");
        assert!(shown.contains("redacted"), "{shown}");
        assert!(!shown.contains("222"), "no byte values: {shown}");
        assert!(!shown.contains("dead"), "no hex: {shown}");
    }
}
