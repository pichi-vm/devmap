// SPDX-License-Identifier: Apache-2.0

//! Password-based key derivation, as LUKS headers specify it.
//!
//! LUKS1 keyslots and both versions' digests use PBKDF2. LUKS2 keyslots
//! default to argon2id, which is memory-hard: the header records the memory
//! and parallelism it was created with, and unlocking has to reproduce them
//! exactly or the derived key is different.

use crate::{Error, Hash, Secret};

/// A key-derivation function together with the parameters a header pins.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kdf {
    /// PBKDF2 with the given hash and iteration count.
    Pbkdf2 {
        /// The PRF hash.
        hash: Hash,
        /// Iteration count.
        iterations: u32,
    },

    /// Argon2, in either the `argon2i` or `argon2id` variant.
    Argon2 {
        /// Whether this is the hybrid `argon2id` (vs data-independent `argon2i`).
        id: bool,
        /// Passes over memory (argon2's "time cost", `t`).
        time: u32,
        /// Memory cost in KiB (`m`).
        memory: u32,
        /// Degree of parallelism (`p`).
        lanes: u32,
    },
}

impl Kdf {
    /// Derive `length` bytes from `passphrase` and `salt`.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] if the parameters are outside what the
    /// underlying implementation accepts (e.g. an argon2 memory cost below
    /// its minimum), which a corrupt or hostile header could ask for.
    pub fn derive(&self, passphrase: &[u8], salt: &[u8], length: usize) -> Result<Secret, Error> {
        let mut out = vec![0u8; length];
        match *self {
            Kdf::Pbkdf2 { hash, iterations } => match hash {
                Hash::Sha1 => {
                    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, salt, iterations, &mut out);
                }
                Hash::Sha256 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, &mut out);
                }
                Hash::Sha512 => {
                    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(passphrase, salt, iterations, &mut out);
                }
            },
            Kdf::Argon2 {
                id,
                time,
                memory,
                lanes,
            } => {
                let algorithm = if id {
                    argon2::Algorithm::Argon2id
                } else {
                    argon2::Algorithm::Argon2i
                };
                let params =
                    argon2::Params::new(memory, time, lanes, Some(length)).map_err(|e| {
                        Error::Unsupported {
                            what: "argon2 parameters",
                            name: e.to_string(),
                        }
                    })?;
                argon2::Argon2::new(algorithm, argon2::Version::V0x13, params)
                    .hash_password_into(passphrase, salt, &mut out)
                    .map_err(|e| Error::Unsupported {
                        what: "argon2 derivation",
                        name: e.to_string(),
                    })?;
            }
        }
        Ok(Secret::new(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_hmac_sha256_matches_a_known_vector() {
        // RFC 7914 §11 test vector: PBKDF2-HMAC-SHA256("passwd", "salt", 1, 64).
        let kdf = Kdf::Pbkdf2 {
            hash: Hash::Sha256,
            iterations: 1,
        };
        let out = kdf.derive(b"passwd", b"salt", 64).expect("derive");
        assert_eq!(
            &out.expose()[..16],
            [
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
                0xb6, 0x05
            ]
        );
    }

    #[test]
    fn argon2id_is_deterministic_and_parameter_sensitive() {
        let base = Kdf::Argon2 {
            id: true,
            time: 2,
            memory: 32,
            lanes: 1,
        };
        let salt = [0x11u8; 16];
        let a = base.derive(b"pass", &salt, 32).expect("derive");
        let b = base.derive(b"pass", &salt, 32).expect("derive again");
        assert_eq!(a.expose(), b.expose(), "same inputs, same key");

        // Every pinned parameter must change the output, else a header that
        // records them would be unlockable with the wrong ones.
        for other in [
            Kdf::Argon2 {
                id: true,
                time: 3,
                memory: 32,
                lanes: 1,
            },
            Kdf::Argon2 {
                id: true,
                time: 2,
                memory: 64,
                lanes: 1,
            },
            Kdf::Argon2 {
                id: true,
                time: 2,
                memory: 32,
                lanes: 2,
            },
            Kdf::Argon2 {
                id: false,
                time: 2,
                memory: 32,
                lanes: 1,
            },
        ] {
            let derived = other.derive(b"pass", &salt, 32).expect("derive");
            assert_ne!(a.expose(), derived.expose(), "{other:?}");
        }
    }

    #[test]
    fn rejects_argon2_parameters_the_implementation_cannot_honour() {
        // A hostile header could name a memory cost below argon2's minimum.
        let kdf = Kdf::Argon2 {
            id: true,
            time: 1,
            memory: 0,
            lanes: 1,
        };
        assert!(kdf.derive(b"pass", &[0u8; 16], 32).is_err());
    }
}
