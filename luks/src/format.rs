// SPDX-License-Identifier: Apache-2.0

//! Creating LUKS1 and LUKS2 volumes.
//!
//! This is the dangerous direction: a wrong offset or a mis-derived
//! keyslot writes a header that either destroys access to the data or
//! silently protects it with the wrong key. Two things keep it honest:
//!
//! - **All randomness is supplied by the caller** through [`Entropy`],
//!   rather than being drawn internally. Production passes `/dev/urandom`;
//!   tests pass a deterministic stream, which makes the output byte-exact
//!   and lets it be compared against a header `cryptsetup` produced from
//!   the same inputs.
//! - Every layout constant below is what `cryptsetup` itself writes, so a
//!   volume created here is an ordinary LUKS volume, not a dialect.
//!
//! Only keyslot 0 is populated; the rest are left empty, exactly as a
//! fresh `cryptsetup luksFormat` leaves them.

use std::io::{Seek, SeekFrom, Write};

use base64::Engine as _;

use crate::header::luks2::BINARY_HEADER_SIZE;
use crate::kdf::Kdf;
use crate::unlock::encrypt_area_aes_xts;
use crate::{Error, Hash, LUKS_MAGIC, LUKS2_SECONDARY_MAGIC, SECTOR_SIZE, Secret, af};

/// AF stripe count; `cryptsetup` uses 4000 for both versions.
pub const AF_STRIPES: usize = 4000;

// -- LUKS2 layout, matching cryptsetup's defaults ---------------------------

/// Total size of one LUKS2 header copy (binary header + JSON area).
const L2_HDR_SIZE: u64 = 16384;
/// Byte offset of the secondary header copy.
const L2_SECONDARY_OFFSET: u64 = L2_HDR_SIZE;
/// Byte offset where the keyslots area begins (after both header copies).
const L2_KEYSLOTS_OFFSET: u64 = 2 * L2_HDR_SIZE;
/// Bytes reserved for one keyslot's AF material (4000 x 64, 4 KiB-aligned).
const L2_KEYSLOT_AREA_SIZE: u64 = 258_048;
/// Total keyslots region, as cryptsetup sizes it for a 16 MiB header.
const L2_KEYSLOTS_SIZE: u64 = 16_744_448;
/// Byte offset of the encrypted payload.
const L2_PAYLOAD_OFFSET: u64 = 16 * 1024 * 1024;

// -- LUKS1 layout -----------------------------------------------------------

/// Byte size of the LUKS1 header struct.
const L1_HEADER_SIZE: usize = 592;
/// Sector offset of keyslot 0's key material.
const L1_SLOT0_OFFSET_SECTORS: u32 = 8;
/// Sector offset of the payload.
const L1_PAYLOAD_OFFSET_SECTORS: u32 = 4096;
/// The `active` marker of a keyslot holding a key.
const L1_KEY_ENABLED: u32 = 0x00AC_71F3;
/// The `active` marker of an empty keyslot.
const L1_KEY_DISABLED: u32 = 0x0000_DEAD;
/// LUKS1 stores a 20-byte master-key digest.
const L1_MK_DIGEST_SIZE: usize = 20;

/// A source of cryptographically secure random bytes.
///
/// Taken as a parameter rather than drawn internally so that the caller
/// owns the entropy decision, and so tests can make formatting
/// deterministic and compare the result byte-for-byte with `cryptsetup`.
pub trait Entropy {
    /// Fill `buf` with random bytes.
    ///
    /// # Errors
    ///
    /// Whatever the underlying source reports.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error>;
}

/// Which on-disk format to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// LUKS1 — a fixed binary header with eight inline keyslots.
    V1,
    /// LUKS2 — a binary header plus JSON metadata, written twice.
    V2,
}

/// How to lay out a new volume. [`Default`] matches `cryptsetup`'s own
/// defaults except for the KDF cost, which a caller should tune.
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// The format version to write.
    pub version: Version,
    /// Cipher spec for the payload, e.g. `aes-xts-plain64`.
    pub cipher: String,
    /// Master key length in bytes (64 = AES-256-XTS).
    pub key_size: usize,
    /// Hash for the AF diffuser and the digests.
    pub hash: Hash,
    /// Keyslot key derivation.
    pub kdf: Kdf,
    /// PBKDF2 iterations for the master-key digest.
    pub digest_iterations: u32,
    /// Volume UUID in canonical hyphenated form.
    pub uuid: String,
    /// Optional volume label (LUKS2 only).
    pub label: String,
    /// Encryption unit in bytes (LUKS2 only; LUKS1 is always 512).
    pub sector_size: u32,
}

impl Default for FormatOptions {
    fn default() -> Self {
        FormatOptions {
            version: Version::V2,
            cipher: "aes-xts-plain64".to_owned(),
            key_size: 64,
            hash: Hash::Sha256,
            kdf: Kdf::Argon2 {
                id: true,
                time: 4,
                memory: 1_048_576,
                lanes: 4,
            },
            digest_iterations: 100_000,
            uuid: String::new(),
            label: String::new(),
            sector_size: 4096,
        }
    }
}

/// What [`format`] produced.
#[derive(Debug)]
pub struct Formatted {
    /// The generated master key. Zeroizes on drop.
    pub master_key: Secret,
    /// Byte offset of the encrypted payload.
    pub payload_offset: u64,
}

/// Write a fresh LUKS volume to `out`, unlockable with `passphrase`.
///
/// Generates a master key, wraps it in keyslot 0, and writes the header(s).
/// Only the header region is written — the payload area is left untouched.
///
/// # Errors
///
/// [`Error::Unsupported`] for options this crate cannot honour,
/// [`Error::Malformed`] for an unusable UUID, or [`Error::Io`] on a write
/// failure.
pub fn format<W: Write + Seek, E: Entropy>(
    out: &mut W,
    options: &FormatOptions,
    passphrase: &[u8],
    entropy: &mut E,
) -> Result<Formatted, Error> {
    if options.cipher != "aes-xts-plain64" {
        return Err(Error::Unsupported {
            what: "cipher",
            name: options.cipher.clone(),
        });
    }
    if options.key_size != 32 && options.key_size != 64 {
        return Err(Error::Unsupported {
            what: "key size",
            name: format!("{} bytes", options.key_size),
        });
    }
    if options.uuid.len() != 36 {
        return Err(Error::Malformed(format!(
            "uuid must be the canonical hyphenated form, got {:?}",
            options.uuid
        )));
    }

    // The master key is what actually protects the data; everything else in
    // the header exists to wrap or describe it.
    let mut master = vec![0u8; options.key_size];
    entropy.fill(&mut master)?;
    let master_key = Secret::new(master);

    match options.version {
        Version::V1 => write_luks1(out, options, passphrase, entropy, &master_key)?,
        Version::V2 => write_luks2(out, options, passphrase, entropy, &master_key)?,
    }

    Ok(Formatted {
        master_key,
        payload_offset: match options.version {
            Version::V1 => u64::from(L1_PAYLOAD_OFFSET_SECTORS) * SECTOR_SIZE,
            Version::V2 => L2_PAYLOAD_OFFSET,
        },
    })
}

/// Build keyslot 0's on-disk material: AF-split the master key and encrypt
/// the result under a key derived from the passphrase.
fn build_keyslot<E: Entropy>(
    options: &FormatOptions,
    passphrase: &[u8],
    entropy: &mut E,
    master_key: &Secret,
    kdf_salt: &[u8],
) -> Result<Vec<u8>, Error> {
    let slot_key = options.kdf.derive(passphrase, kdf_salt, options.key_size)?;

    let mut random = vec![0u8; options.key_size * (AF_STRIPES - 1)];
    entropy.fill(&mut random)?;
    let mut split = af::split(master_key.expose(), AF_STRIPES, options.hash, &random)
        .ok_or_else(|| Error::Malformed("AF split rejected its inputs".to_owned()))?;
    encrypt_area_aes_xts(&mut split, slot_key.expose())?;
    Ok(split)
}

/// Write a NUL-padded fixed-width string field.
fn put_str(buf: &mut [u8], at: usize, width: usize, value: &str) {
    let bytes = value.as_bytes();
    let n = bytes.len().min(width);
    buf[at..at + n].copy_from_slice(&bytes[..n]);
}

fn write_luks1<W: Write + Seek, E: Entropy>(
    out: &mut W,
    options: &FormatOptions,
    passphrase: &[u8],
    entropy: &mut E,
    master_key: &Secret,
) -> Result<(), Error> {
    // LUKS1 names the cipher and mode in separate fields.
    let (cipher_name, cipher_mode) =
        options
            .cipher
            .split_once('-')
            .ok_or_else(|| Error::Unsupported {
                what: "cipher spec",
                name: options.cipher.clone(),
            })?;

    let mut salt = [0u8; 32];
    entropy.fill(&mut salt)?;
    let mut mk_salt = [0u8; 32];
    entropy.fill(&mut mk_salt)?;

    // LUKS1's keyslots always use PBKDF2 with the header's hash.
    let slot_kdf = match options.kdf {
        Kdf::Pbkdf2 { iterations, .. } => Kdf::Pbkdf2 {
            hash: options.hash,
            iterations,
        },
        Kdf::Argon2 { .. } => {
            return Err(Error::Unsupported {
                what: "LUKS1 keyslot kdf",
                name: "argon2 (LUKS1 supports only pbkdf2)".to_owned(),
            });
        }
    };
    let slot_options = FormatOptions {
        kdf: slot_kdf.clone(),
        ..options.clone()
    };
    let material = build_keyslot(&slot_options, passphrase, entropy, master_key, &salt)?;

    let mk_digest = Kdf::Pbkdf2 {
        hash: options.hash,
        iterations: options.digest_iterations,
    }
    .derive(master_key.expose(), &mk_salt, L1_MK_DIGEST_SIZE)?;

    let mut header = vec![0u8; L1_HEADER_SIZE];
    header[0..6].copy_from_slice(&LUKS_MAGIC);
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    put_str(&mut header, 8, 32, cipher_name);
    put_str(&mut header, 40, 32, cipher_mode);
    put_str(&mut header, 72, 32, options.hash.spec());
    header[104..108].copy_from_slice(&L1_PAYLOAD_OFFSET_SECTORS.to_be_bytes());
    header[108..112].copy_from_slice(&key_size_u32(options)?.to_be_bytes());
    header[112..132].copy_from_slice(mk_digest.expose());
    header[132..164].copy_from_slice(&mk_salt);
    header[164..168].copy_from_slice(&options.digest_iterations.to_be_bytes());
    put_str(&mut header, 168, 40, &options.uuid);

    // Slot 0 holds the key; the other seven are disabled. Every slot still
    // gets a valid stripe count and a non-overlapping material offset:
    // cryptsetup validates the geometry of disabled slots too, and rejects
    // the whole volume ("LUKS keyslot N is invalid") if they are left zero.
    let iterations = match slot_kdf {
        Kdf::Pbkdf2 { iterations, .. } => iterations,
        Kdf::Argon2 { .. } => unreachable!("rejected above"),
    };
    let stride = slot_stride_sectors(options)?;
    for slot in 0..8u32 {
        let base = 208 + slot as usize * 48;
        let active = if slot == 0 {
            L1_KEY_ENABLED
        } else {
            L1_KEY_DISABLED
        };
        header[base..base + 4].copy_from_slice(&active.to_be_bytes());
        if slot == 0 {
            header[base + 4..base + 8].copy_from_slice(&iterations.to_be_bytes());
            header[base + 8..base + 40].copy_from_slice(&salt);
        }
        let offset = L1_SLOT0_OFFSET_SECTORS + slot * stride;
        header[base + 40..base + 44].copy_from_slice(&offset.to_be_bytes());
        header[base + 44..base + 48].copy_from_slice(&u32_of(AF_STRIPES)?.to_be_bytes());
    }

    out.seek(SeekFrom::Start(0))?;
    out.write_all(&header)?;
    out.seek(SeekFrom::Start(
        u64::from(L1_SLOT0_OFFSET_SECTORS) * SECTOR_SIZE,
    ))?;
    out.write_all(&material)?;
    out.flush()?;
    Ok(())
}

fn write_luks2<W: Write + Seek, E: Entropy>(
    out: &mut W,
    options: &FormatOptions,
    passphrase: &[u8],
    entropy: &mut E,
    master_key: &Secret,
) -> Result<(), Error> {
    let mut kdf_salt = [0u8; 32];
    entropy.fill(&mut kdf_salt)?;
    let mut digest_salt = [0u8; 32];
    entropy.fill(&mut digest_salt)?;

    let material = build_keyslot(options, passphrase, entropy, master_key, &kdf_salt)?;
    if u64::try_from(material.len()).unwrap_or(u64::MAX) > L2_KEYSLOT_AREA_SIZE {
        return Err(Error::Malformed(format!(
            "keyslot material is {} bytes, larger than the {L2_KEYSLOT_AREA_SIZE}-byte area",
            material.len()
        )));
    }

    let digest = Kdf::Pbkdf2 {
        hash: options.hash,
        iterations: options.digest_iterations,
    }
    .derive(
        master_key.expose(),
        &digest_salt,
        options.hash.digest_size(),
    )?;

    let json = build_json(options, &kdf_salt, &digest_salt, digest.expose())?;
    let json_area_size = usize::try_from(L2_HDR_SIZE).expect("fits") - BINARY_HEADER_SIZE;
    if json.len() > json_area_size {
        return Err(Error::Malformed(format!(
            "JSON metadata is {} bytes, larger than the {json_area_size}-byte area",
            json.len()
        )));
    }

    // Both copies are identical apart from their magic and hdr_offset, and
    // each carries a checksum over its own bytes.
    for (offset, magic) in [
        (0u64, LUKS_MAGIC),
        (L2_SECONDARY_OFFSET, LUKS2_SECONDARY_MAGIC),
    ] {
        let mut copy = vec![0u8; usize::try_from(L2_HDR_SIZE).expect("fits")];
        copy[0..6].copy_from_slice(&magic);
        copy[6..8].copy_from_slice(&2u16.to_be_bytes());
        copy[8..16].copy_from_slice(&L2_HDR_SIZE.to_be_bytes());
        // A fresh volume starts at sequence id 1.
        copy[16..24].copy_from_slice(&1u64.to_be_bytes());
        put_str(&mut copy, 24, 48, &options.label);
        put_str(&mut copy, 72, 32, options.hash.spec());
        put_str(&mut copy, 168, 40, &options.uuid);
        copy[256..264].copy_from_slice(&offset.to_be_bytes());
        copy[BINARY_HEADER_SIZE..BINARY_HEADER_SIZE + json.len()].copy_from_slice(&json);

        // The checksum covers the whole copy with the field zeroed.
        let csum = options.hash.digest(&copy);
        copy[448..448 + csum.len()].copy_from_slice(&csum);

        out.seek(SeekFrom::Start(offset))?;
        out.write_all(&copy)?;
    }

    out.seek(SeekFrom::Start(L2_KEYSLOTS_OFFSET))?;
    out.write_all(&material)?;
    out.flush()?;
    Ok(())
}

/// Render the LUKS2 JSON metadata for a single-keyslot volume.
///
/// Byte offsets and sizes go out as JSON *strings*, which is what the
/// format requires and what a reader will expect.
fn build_json(
    options: &FormatOptions,
    kdf_salt: &[u8],
    digest_salt: &[u8],
    digest: &[u8],
) -> Result<Vec<u8>, Error> {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

    let kdf = match &options.kdf {
        Kdf::Argon2 {
            id,
            time,
            memory,
            lanes,
        } => serde_json::json!({
            "type": if *id { "argon2id" } else { "argon2i" },
            "time": time,
            "memory": memory,
            "cpus": lanes,
            "salt": b64(kdf_salt),
        }),
        Kdf::Pbkdf2 { hash, iterations } => serde_json::json!({
            "type": "pbkdf2",
            "hash": hash.spec(),
            "iterations": iterations,
            "salt": b64(kdf_salt),
        }),
    };

    let document = serde_json::json!({
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": options.key_size,
                "af": {
                    "type": "luks1",
                    "stripes": AF_STRIPES,
                    "hash": options.hash.spec(),
                },
                "area": {
                    "type": "raw",
                    "offset": L2_KEYSLOTS_OFFSET.to_string(),
                    "size": L2_KEYSLOT_AREA_SIZE.to_string(),
                    "encryption": options.cipher,
                    "key_size": options.key_size,
                },
                "kdf": kdf,
            }
        },
        "tokens": {},
        "segments": {
            "0": {
                "type": "crypt",
                "offset": L2_PAYLOAD_OFFSET.to_string(),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": options.cipher,
                "sector_size": options.sector_size,
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": options.hash.spec(),
                "iterations": options.digest_iterations,
                "salt": b64(digest_salt),
                "digest": b64(digest),
            }
        },
        "config": {
            "json_size": (L2_HDR_SIZE - BINARY_HEADER_SIZE as u64).to_string(),
            "keyslots_size": L2_KEYSLOTS_SIZE.to_string(),
        }
    });

    serde_json::to_vec(&document).map_err(Error::Json)
}

/// Sectors between consecutive LUKS1 keyslots: one slot's AF material,
/// rounded up to a 4 KiB boundary, as cryptsetup lays them out.
fn slot_stride_sectors(options: &FormatOptions) -> Result<u32, Error> {
    let material = options.key_size * AF_STRIPES;
    let aligned = material.div_ceil(4096) * 4096;
    u32_of(aligned / usize::try_from(SECTOR_SIZE).expect("512 fits usize"))
}

/// The key size as a `u32` header field.
fn key_size_u32(options: &FormatOptions) -> Result<u32, Error> {
    u32::try_from(options.key_size)
        .map_err(|_| Error::Malformed("key size out of range".to_owned()))
}

fn u32_of(value: usize) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::Malformed("value out of range".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::Header;

    /// A deterministic byte stream, so a formatted volume is reproducible.
    struct Counter(u8);
    impl Entropy for Counter {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            for byte in buf.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn cheap(version: Version) -> FormatOptions {
        FormatOptions {
            version,
            kdf: Kdf::Pbkdf2 {
                hash: Hash::Sha256,
                iterations: 1000,
            },
            digest_iterations: 1000,
            uuid: "1b4e28ba-2fa1-11d2-883f-0016d3cca427".to_owned(),
            ..FormatOptions::default()
        }
    }

    /// Format into a buffer big enough to hold the header region.
    fn format_to_buffer(options: &FormatOptions, passphrase: &[u8]) -> (Vec<u8>, Secret) {
        let mut buf = Cursor::new(vec![0u8; 32 * 1024 * 1024]);
        let out = format(&mut buf, options, passphrase, &mut Counter(1)).expect("format");
        (buf.into_inner(), out.master_key)
    }

    #[test]
    fn luks1_round_trips_through_our_own_reader() {
        let options = cheap(Version::V1);
        let (image, master_key) = format_to_buffer(&options, b"open sesame");

        let header = Header::parse(&image).expect("parse what we wrote");
        assert_eq!(header.version(), 1);
        assert_eq!(header.uuid(), options.uuid);
        assert_eq!(header.cipher_spec().unwrap(), "aes-xts-plain64");

        let recovered = header
            .unlock(b"open sesame", &image.as_slice())
            .expect("unlock what we wrote");
        assert_eq!(
            recovered.expose(),
            master_key.expose(),
            "the keyslot must wrap the master key we generated"
        );
    }

    #[test]
    fn luks2_round_trips_through_our_own_reader() {
        let options = cheap(Version::V2);
        let (image, master_key) = format_to_buffer(&options, b"open sesame");

        let header = Header::parse(&image).expect("parse what we wrote");
        assert_eq!(header.version(), 2);
        assert_eq!(header.uuid(), options.uuid);
        assert_eq!(header.sector_size(), 4096);
        assert_eq!(header.payload_offset_bytes().unwrap(), L2_PAYLOAD_OFFSET);

        let recovered = header
            .unlock(b"open sesame", &image.as_slice())
            .expect("unlock what we wrote");
        assert_eq!(recovered.expose(), master_key.expose());
    }

    #[test]
    fn a_wrong_passphrase_does_not_unlock_what_we_wrote() {
        for version in [Version::V1, Version::V2] {
            let (image, _) = format_to_buffer(&cheap(version), b"right");
            let header = Header::parse(&image).expect("parse");
            assert!(
                matches!(
                    header.unlock(b"wrong", &image.as_slice()),
                    Err(Error::NoKey)
                ),
                "{version:?}"
            );
        }
    }

    #[test]
    fn luks2_writes_a_usable_secondary_header() {
        let (mut image, _) = format_to_buffer(&cheap(Version::V2), b"pass");
        // Corrupt the primary copy; the secondary must carry the volume.
        image[100] ^= 0xFF;
        let header = Header::parse(&image).expect("fall back to the secondary header");
        assert_eq!(header.version(), 2);
        let recovered = header.unlock(b"pass", &image.as_slice());
        assert!(recovered.is_ok(), "secondary header still unlocks");
    }

    #[test]
    fn formatting_is_deterministic_for_a_given_entropy_stream() {
        // This is what makes a byte-comparison against cryptsetup possible.
        let options = cheap(Version::V2);
        let (a, _) = format_to_buffer(&options, b"pass");
        let (b, _) = format_to_buffer(&options, b"pass");
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_options_it_cannot_honour() {
        let bad_cipher = FormatOptions {
            cipher: "serpent-cbc-essiv:sha256".to_owned(),
            ..cheap(Version::V2)
        };
        let mut buf = Cursor::new(vec![0u8; 1024]);
        assert!(format(&mut buf, &bad_cipher, b"p", &mut Counter(1)).is_err());

        let bad_uuid = FormatOptions {
            uuid: "not-a-uuid".to_owned(),
            ..cheap(Version::V2)
        };
        assert!(format(&mut buf, &bad_uuid, b"p", &mut Counter(1)).is_err());

        // LUKS1 has no argon2 keyslots; silently downgrading would be worse
        // than refusing.
        let argon_on_luks1 = FormatOptions {
            kdf: Kdf::Argon2 {
                id: true,
                time: 1,
                memory: 32,
                lanes: 1,
            },
            ..cheap(Version::V1)
        };
        assert!(format(&mut buf, &argon_on_luks1, b"p", &mut Counter(1)).is_err());
    }
}
