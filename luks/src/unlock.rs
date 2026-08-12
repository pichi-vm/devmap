// SPDX-License-Identifier: Apache-2.0

//! Recovering the master key from a passphrase.
//!
//! Per keyslot: derive a key from the passphrase, decrypt the slot's
//! keyslot area with it, [`af`](crate::af)-merge the plaintext to get a
//! candidate master key, and check that candidate against the header's
//! digest. The digest check is what makes a wrong passphrase a clean
//! [`Error::NoKey`] rather than a garbage key.

use aes::cipher::KeyInit as _;
use xts_mode::{Xts128, get_tweak_default};

use crate::header::Header;
use crate::{Error, SECTOR_SIZE, Secret, af};

/// The recovered master key. Zeroizes on drop and redacts in `Debug`.
pub type MasterKey = Secret;

/// Reads the keyslot areas of a volume — the part of unlocking that needs
/// the device, kept behind a trait so the pure crypto stays testable.
pub trait KeyslotAreas {
    /// Read exactly `len` bytes at byte `offset` from the volume.
    ///
    /// # Errors
    ///
    /// The underlying I/O error.
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error>;
}

impl KeyslotAreas for std::fs::File {
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error> {
        use std::os::unix::fs::FileExt as _;
        let mut buf = vec![0u8; len];
        self.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }
}

impl KeyslotAreas for &[u8] {
    fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error> {
        // A header can name any offset it likes, so the range has to be
        // computed without overflowing.
        let end = usize::try_from(offset)
            .ok()
            .and_then(|start| start.checked_add(len).map(|end| (start, end)));
        let Some((start, end)) = end else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "keyslot offset out of range",
            ));
        };
        self.get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short buffer"))
    }
}

/// Decrypt a keyslot area in place with AES-XTS.
///
/// The area is treated as a sequence of 512-byte sectors numbered from
/// zero, which is what `plain64` means for a keyslot area: the tweak is the
/// sector index within the area, not within the device.
fn decrypt_area_aes_xts(area: &mut [u8], key: &[u8]) -> Result<(), Error> {
    let sector_size = usize::try_from(SECTOR_SIZE).expect("512 fits usize");
    // XTS splits the key in half: one half encrypts, the other tweaks. So a
    // 32-byte key is AES-128-XTS and a 64-byte key is AES-256-XTS.
    match key.len() {
        32 => {
            let (cipher, tweak) = key.split_at(16);
            let xts = Xts128::new(
                aes::Aes128::new_from_slice(cipher).map_err(|_| bad_key())?,
                aes::Aes128::new_from_slice(tweak).map_err(|_| bad_key())?,
            );
            xts.decrypt_area(area, sector_size, 0, get_tweak_default);
            Ok(())
        }
        64 => {
            let (cipher, tweak) = key.split_at(32);
            let xts = Xts128::new(
                aes::Aes256::new_from_slice(cipher).map_err(|_| bad_key())?,
                aes::Aes256::new_from_slice(tweak).map_err(|_| bad_key())?,
            );
            xts.decrypt_area(area, sector_size, 0, get_tweak_default);
            Ok(())
        }
        other => Err(Error::Unsupported {
            what: "aes-xts key size",
            name: format!("{} bits", other * 8),
        }),
    }
}

fn bad_key() -> Error {
    Error::Unsupported {
        what: "aes key",
        name: "invalid length".to_owned(),
    }
}

impl Header {
    /// Recover the master key by trying `passphrase` against every active
    /// keyslot, in order.
    ///
    /// # Errors
    ///
    /// [`Error::NoKey`] if no keyslot accepts the passphrase, or an I/O or
    /// algorithm error from reading and decrypting a slot.
    pub fn unlock<A: KeyslotAreas>(
        &self,
        passphrase: &[u8],
        areas: &A,
    ) -> Result<MasterKey, Error> {
        match self {
            Header::V1(header) => {
                let key_bytes = usize::try_from(header.key_bytes)
                    .map_err(|_| Error::Malformed("key-bytes out of range".to_owned()))?;

                for slot in header.keyslots.iter().filter(|s| s.active) {
                    let stripes = usize::try_from(slot.stripes)
                        .map_err(|_| Error::Malformed("stripes out of range".to_owned()))?;

                    // Derive the slot key and decrypt its AF-split material.
                    let slot_key = header
                        .keyslot_kdf(slot)
                        .derive(passphrase, &slot.salt, key_bytes)?;
                    let offset = u64::from(slot.key_material_offset) * SECTOR_SIZE;
                    let mut area = areas.read_at(offset, key_bytes * stripes)?;
                    decrypt_area_aes_xts(&mut area, slot_key.expose())?;

                    // Merge the stripes back into a candidate master key and
                    // check it; a wrong passphrase simply fails here.
                    let candidate = af::merge(&area, key_bytes, stripes, header.hash)
                        .ok_or_else(|| Error::Malformed("keyslot area is short".to_owned()))?;
                    let matches = header.verify_master_key(&candidate);
                    let candidate = Secret::new(candidate);
                    if matches {
                        return Ok(candidate);
                    }
                }
                Err(Error::NoKey)
            }
            Header::V2(header) => {
                for (index, slot) in &header.metadata.keyslots {
                    if slot.kind != "luks2" || slot.af.kind != "luks1" || slot.area.kind != "raw" {
                        // A slot shape this crate does not implement (e.g. a
                        // reencryption slot); skip rather than fail, so other
                        // slots still get a chance.
                        continue;
                    }
                    let Some(digest) = header.metadata.digest_for(index) else {
                        continue;
                    };
                    let hash = crate::Hash::from_spec(&slot.af.hash).ok_or(Error::Unsupported {
                        what: "af hash",
                        name: slot.af.hash.clone(),
                    })?;

                    // Derive the slot key, decrypt the slot's area, merge.
                    let kdf = kdf_from_spec(&slot.kdf)?;
                    let slot_key = kdf.derive(passphrase, &slot.kdf.salt, slot.area.key_size)?;
                    let split_len = slot.key_size * slot.af.stripes;
                    if u64::try_from(split_len).unwrap_or(u64::MAX) > slot.area.size {
                        return Err(Error::Malformed(format!(
                            "keyslot {index} needs {split_len} bytes but its area holds {}",
                            slot.area.size
                        )));
                    }
                    let mut area = areas.read_at(slot.area.offset, split_len)?;
                    decrypt_area(&slot.area.encryption, &mut area, slot_key.expose())?;

                    let candidate = af::merge(&area, slot.key_size, slot.af.stripes, hash)
                        .ok_or_else(|| Error::Malformed("keyslot area is short".to_owned()))?;
                    let matches = verify_digest(digest, &candidate)?;
                    let candidate = Secret::new(candidate);
                    if matches {
                        return Ok(candidate);
                    }
                }
                Err(Error::NoKey)
            }
        }
    }
}

/// Build a [`Kdf`] from a LUKS2 keyslot's JSON parameters.
fn kdf_from_spec(spec: &crate::header::json::KdfSpec) -> Result<crate::kdf::Kdf, Error> {
    match spec.kind.as_str() {
        "argon2i" | "argon2id" => Ok(crate::kdf::Kdf::Argon2 {
            id: spec.kind == "argon2id",
            time: spec.time,
            memory: spec.memory,
            lanes: spec.cpus,
        }),
        "pbkdf2" => {
            let name = spec.hash.clone().unwrap_or_default();
            let hash = crate::Hash::from_spec(&name).ok_or(Error::Unsupported {
                what: "keyslot hash",
                name,
            })?;
            Ok(crate::kdf::Kdf::Pbkdf2 {
                hash,
                iterations: spec.iterations,
            })
        }
        other => Err(Error::Unsupported {
            what: "keyslot kdf",
            name: other.to_owned(),
        }),
    }
}

/// Check a candidate master key against a LUKS2 digest.
fn verify_digest(digest: &crate::header::json::Digest, candidate: &[u8]) -> Result<bool, Error> {
    if digest.kind != "pbkdf2" {
        return Err(Error::Unsupported {
            what: "digest",
            name: digest.kind.clone(),
        });
    }
    let hash = crate::Hash::from_spec(&digest.hash).ok_or(Error::Unsupported {
        what: "digest hash",
        name: digest.hash.clone(),
    })?;
    let derived = crate::kdf::Kdf::Pbkdf2 {
        hash,
        iterations: digest.iterations,
    }
    .derive(candidate, &digest.salt, digest.digest.len())?;
    // Compare every byte, with no early exit.
    Ok(derived
        .expose()
        .iter()
        .zip(&digest.digest)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0)
}

/// Decrypt a keyslot area whose cipher is named by a LUKS2 `encryption`
/// spec. Only AES-XTS is implemented, which is what cryptsetup writes.
fn decrypt_area(encryption: &str, area: &mut [u8], key: &[u8]) -> Result<(), Error> {
    if encryption != "aes-xts-plain64" {
        return Err(Error::Unsupported {
            what: "keyslot area cipher",
            name: encryption.to_owned(),
        });
    }
    decrypt_area_aes_xts(area, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_reader_rejects_reads_past_the_end() {
        let data = [0u8; 16];
        let slice = &data[..];
        assert!(slice.read_at(0, 16).is_ok());
        assert!(slice.read_at(8, 16).is_err());
        assert!(slice.read_at(u64::MAX, 1).is_err());
    }

    #[test]
    fn rejects_an_unsupported_xts_key_size() {
        let mut area = [0u8; 512];
        assert!(matches!(
            decrypt_area_aes_xts(&mut area, &[0u8; 20]),
            Err(Error::Unsupported { .. })
        ));
    }

    #[test]
    fn aes_xts_decrypt_is_the_inverse_of_encrypt() {
        // Round-trip through the same construction the unlock path uses, so
        // a wrong key split or tweak convention shows up here.
        let key = [0x2bu8; 64];
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let mut buf = plaintext.clone();

        let (first, second) = key.split_at(32);
        let xts = Xts128::new(
            aes::Aes256::new_from_slice(first).unwrap(),
            aes::Aes256::new_from_slice(second).unwrap(),
        );
        xts.encrypt_area(&mut buf, 512, 0, get_tweak_default);
        assert_ne!(buf, plaintext, "encryption must change the bytes");

        decrypt_area_aes_xts(&mut buf, &key).expect("decrypt");
        assert_eq!(buf, plaintext);
    }
}
