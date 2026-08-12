// SPDX-License-Identifier: Apache-2.0

//! The `crypt` (dm-crypt) target: transparent encryption of a block
//! device through the kernel crypto API.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use crate::DevId;
use crate::table::{NoInfo, Params, ParseError, Target};

/// Where dm-crypt gets the key for a mapping.
///
/// The keyring form is what `cryptsetup` uses in practice: a `logon` key
/// cannot be read back from userspace, so the master key never appears in
/// `dmsetup table --showkeys`. Prefer it over [`Key::Hex`], which puts the
/// raw key in the kernel's table string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Key {
    /// Raw key bytes, rendered into the table as lowercase hex.
    Hex(Vec<u8>),

    /// A key held in the kernel keyring, rendered as
    /// `:<size>:<type>:<description>`.
    Keyring {
        /// Key size in bytes; must match the keyring payload's size.
        size: u32,
        /// The keyring key type.
        kind: KeyType,
        /// The key description dm-crypt looks the key up by.
        description: String,
    },

    /// No key — the kernel's `-`, which it emits once a key has been wiped.
    Absent,
}

impl Key {
    /// The key size in bytes, as the kernel accounts for it.
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Key::Hex(bytes) => bytes.len(),
            Key::Keyring { size, .. } => *size as usize,
            Key::Absent => 0,
        }
    }
}

/// `Display` is the wire codec, so it must emit the real key. `Debug` is
/// for humans and logs, so it must not: it reports only the shape.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Hex(bytes) => write!(f, "Key::Hex(<{} bytes redacted>)", bytes.len()),
            Key::Keyring {
                size,
                kind,
                description,
            } => f
                .debug_struct("Key::Keyring")
                .field("size", size)
                .field("kind", kind)
                .field("description", description)
                .finish(),
            Key::Absent => f.write_str("Key::Absent"),
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Hex(bytes) => {
                for b in bytes {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Key::Keyring {
                size,
                kind,
                description,
            } => write!(f, ":{size}:{kind}:{description}"),
            Key::Absent => f.write_char('-'),
        }
    }
}

/// The kernel keyring key types dm-crypt accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// `logon` — payload is not readable from userspace. What cryptsetup uses.
    Logon,
    /// `user` — payload is readable by a process with permission.
    User,
    /// `encrypted` — kernel-encrypted key material.
    Encrypted,
    /// `trusted` — key sealed by a trust source (e.g. a TPM).
    Trusted,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyType::Logon => "logon",
            KeyType::User => "user",
            KeyType::Encrypted => "encrypted",
            KeyType::Trusted => "trusted",
        })
    }
}

impl FromStr for KeyType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "logon" => Ok(KeyType::Logon),
            "user" => Ok(KeyType::User),
            "encrypted" => Ok(KeyType::Encrypted),
            "trusted" => Ok(KeyType::Trusted),
            _ => Err(ParseError),
        }
    }
}

/// Per-sector integrity metadata carried alongside the ciphertext, stored
/// by an underlying dm-integrity device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integrity {
    /// Metadata bytes per sector.
    pub tag_size: u32,
    /// `none` for a persistent IV only, `aead` for authenticated encryption.
    pub kind: String,
}

/// Transparent encryption of `device`. Build with [`Crypt::new`] and set
/// the optional fields directly; they render in the kernel's own argument
/// order, so a row read back from `DM_TABLE_STATUS` round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
// Mirrors dm-crypt's bare optional flags, which are independent booleans.
#[allow(clippy::struct_excessive_bools)]
pub struct Crypt {
    /// `cipher[:keycount]-chainmode-ivmode[:ivopts]`, or a `capi:` spec.
    pub cipher: String,
    /// The encryption key.
    pub key: Key,
    /// Sector count added to the sector number before deriving the IV.
    pub iv_offset: u64,
    /// The backing device holding the ciphertext.
    pub device: DevId,
    /// Starting sector within `device` where the encrypted data begins.
    pub offset: u64,
    /// Pass discards through to the backing device.
    pub allow_discards: bool,
    /// Encrypt on the CPU that submitted the I/O.
    pub same_cpu_crypt: bool,
    /// Run the crypt workqueues and writer thread at high priority.
    pub high_priority: bool,
    /// Submit writes from the encryption thread instead of offloading.
    pub submit_from_crypt_cpus: bool,
    /// Process reads synchronously, bypassing the internal workqueue.
    pub no_read_workqueue: bool,
    /// Process writes synchronously, bypassing the internal workqueue.
    pub no_write_workqueue: bool,
    /// Per-sector integrity metadata, if the mapping carries any.
    pub integrity: Option<Integrity>,
    /// Encryption unit in bytes when it isn't the 512-byte sector.
    pub sector_size: Option<u32>,
    /// Count IV sectors in `sector_size` units rather than 512 bytes.
    pub iv_large_sectors: bool,
    /// Integrity key size, when it differs from the digest size.
    pub integrity_key_size: Option<u32>,
}

impl Crypt {
    /// A mapping of `device` under `cipher` with `key`, starting at sector
    /// 0 with no IV offset and no optional features.
    #[must_use]
    pub fn new(cipher: impl Into<String>, key: Key, device: DevId) -> Self {
        Crypt {
            cipher: cipher.into(),
            key,
            iv_offset: 0,
            device,
            offset: 0,
            allow_discards: false,
            same_cpu_crypt: false,
            high_priority: false,
            submit_from_crypt_cpus: false,
            no_read_workqueue: false,
            no_write_workqueue: false,
            integrity: None,
            sector_size: None,
            iv_large_sectors: false,
            integrity_key_size: None,
        }
    }
}

impl Target for Crypt {
    const NAME: &'static str = "crypt";
    type Table = Self;
    // dm-crypt's STATUSTYPE_INFO writes an empty string — it reports no
    // runtime state at all.
    type Info = NoInfo;
}

impl fmt::Display for Crypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.cipher, self.key, self.iv_offset, self.device, self.offset
        )?;

        // Argument order follows dm-crypt's own status emission, so a
        // parsed row renders back byte-for-byte.
        let mut args: Vec<String> = Vec::new();
        for (set, name) in [
            (self.allow_discards, "allow_discards"),
            (self.same_cpu_crypt, "same_cpu_crypt"),
            (self.high_priority, "high_priority"),
            (self.submit_from_crypt_cpus, "submit_from_crypt_cpus"),
            (self.no_read_workqueue, "no_read_workqueue"),
            (self.no_write_workqueue, "no_write_workqueue"),
        ] {
            if set {
                args.push(name.to_owned());
            }
        }
        if let Some(integrity) = &self.integrity {
            args.push(format!(
                "integrity:{}:{}",
                integrity.tag_size, integrity.kind
            ));
        }
        if let Some(sector_size) = self.sector_size {
            args.push(format!("sector_size:{sector_size}"));
        }
        if self.iv_large_sectors {
            args.push("iv_large_sectors".to_owned());
        }
        if let Some(size) = self.integrity_key_size {
            args.push(format!("integrity_key_size:{size}"));
        }

        // The kernel omits the count entirely when there are no optional
        // arguments, so match that rather than emitting a bare "0".
        if !args.is_empty() {
            write!(f, " {}", args.len())?;
            for arg in &args {
                write!(f, " {arg}")?;
            }
        }
        Ok(())
    }
}

/// Decode the `<key>` field, which is `-`, a `:size:type:description`
/// keyring reference, or lowercase hex.
fn parse_key(token: &str) -> Result<Key, ParseError> {
    if token == "-" {
        return Ok(Key::Absent);
    }
    if let Some(rest) = token.strip_prefix(':') {
        // `<size>:<type>:<description>` — the description may itself contain
        // colons (cryptsetup uses `cryptsetup:<uuid>-d0`), so split only twice.
        let (size, rest) = rest.split_once(':').ok_or(ParseError)?;
        let (kind, description) = rest.split_once(':').ok_or(ParseError)?;
        if description.is_empty() {
            return Err(ParseError);
        }
        return Ok(Key::Keyring {
            size: size.parse().map_err(|_| ParseError)?,
            kind: kind.parse()?,
            description: description.to_owned(),
        });
    }
    if token.is_empty() || !token.len().is_multiple_of(2) {
        return Err(ParseError);
    }
    (0..token.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&token[i..i + 2], 16).map_err(|_| ParseError))
        .collect::<Result<Vec<u8>, _>>()
        .map(Key::Hex)
}

impl FromStr for Crypt {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let cipher = p.token()?.to_owned();
        let key = parse_key(p.token()?)?;
        let iv_offset = p.value()?;
        let device = p.device()?;
        let offset = p.value()?;

        let mut crypt = Crypt {
            cipher,
            key,
            iv_offset,
            device,
            offset,
            allow_discards: false,
            same_cpu_crypt: false,
            high_priority: false,
            submit_from_crypt_cpus: false,
            no_read_workqueue: false,
            no_write_workqueue: false,
            integrity: None,
            sector_size: None,
            iv_large_sectors: false,
            integrity_key_size: None,
        };

        // The optional-argument section is omitted entirely when empty.
        if p.remaining() == 0 {
            return Ok(crypt);
        }

        // Every optional argument is a single token, either a bare flag or a
        // `key:value` pair, so the count is a token count.
        let count: usize = p.value()?;
        for _ in 0..count {
            let arg = p.token()?;
            match arg {
                "allow_discards" => crypt.allow_discards = true,
                "same_cpu_crypt" => crypt.same_cpu_crypt = true,
                "high_priority" => crypt.high_priority = true,
                "submit_from_crypt_cpus" => crypt.submit_from_crypt_cpus = true,
                "no_read_workqueue" => crypt.no_read_workqueue = true,
                "no_write_workqueue" => crypt.no_write_workqueue = true,
                "iv_large_sectors" => crypt.iv_large_sectors = true,
                _ => {
                    let (key, value) = arg.split_once(':').ok_or(ParseError)?;
                    match key {
                        "integrity" => {
                            // `<bytes>:<type>`; the type is the remainder.
                            let (tag_size, kind) = value.split_once(':').ok_or(ParseError)?;
                            crypt.integrity = Some(Integrity {
                                tag_size: tag_size.parse().map_err(|_| ParseError)?,
                                kind: kind.to_owned(),
                            });
                        }
                        "sector_size" => {
                            crypt.sector_size = Some(value.parse().map_err(|_| ParseError)?);
                        }
                        "integrity_key_size" => {
                            crypt.integrity_key_size = Some(value.parse().map_err(|_| ParseError)?);
                        }
                        _ => return Err(ParseError),
                    }
                }
            }
        }
        p.end()?;
        Ok(crypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    fn dev() -> DevId {
        DevId::new(252, 1).unwrap()
    }

    fn crypt() -> Crypt {
        Crypt::new("aes-xts-plain64", Key::Hex(vec![0xAB; 32]), dev())
    }

    #[test]
    fn crypt_renders_the_minimal_row_without_an_optional_count() {
        // The kernel omits the count when there are no optional arguments.
        assert_eq!(
            line(0, 8192, &crypt()),
            format!("0 8192 crypt aes-xts-plain64 {} 0 252:1 0", "ab".repeat(32))
        );
    }

    #[test]
    fn crypt_renders_optional_args_in_kernel_order() {
        let t = Crypt {
            allow_discards: true,
            no_read_workqueue: true,
            sector_size: Some(4096),
            iv_large_sectors: true,
            integrity: Some(Integrity {
                tag_size: 32,
                kind: "aead".to_owned(),
            }),
            ..crypt()
        };
        let rendered = t.to_string();
        assert!(
            rendered.ends_with(
                "5 allow_discards no_read_workqueue integrity:32:aead \
                 sector_size:4096 iv_large_sectors"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn crypt_display_from_str_round_trips() {
        for t in [
            crypt(),
            Crypt {
                key: Key::Keyring {
                    size: 64,
                    kind: KeyType::Logon,
                    // cryptsetup's descriptions contain colons.
                    description: "cryptsetup:1234-abcd-d0".to_owned(),
                },
                iv_offset: 7,
                offset: 4096,
                allow_discards: true,
                same_cpu_crypt: true,
                high_priority: true,
                submit_from_crypt_cpus: true,
                no_write_workqueue: true,
                sector_size: Some(4096),
                integrity_key_size: Some(32),
                ..crypt()
            },
            Crypt {
                key: Key::Absent,
                ..crypt()
            },
        ] {
            let rendered = t.to_string();
            assert_eq!(rendered.parse::<Crypt>().as_ref(), Ok(&t), "{rendered}");
        }
    }

    #[test]
    fn crypt_parses_the_row_the_kernel_reported() {
        // Captured from a live dm-crypt device (key masked by dmsetup).
        let reported = format!("aes-xts-plain64 {} 0 7:0 0", "0".repeat(64));
        let table: Crypt = reported.parse().expect("parse");
        assert_eq!(table.cipher, "aes-xts-plain64");
        assert_eq!(table.key.size(), 32);
        assert_eq!(table.device, DevId::new(7, 0).unwrap());
        assert_eq!(table.to_string(), reported);
    }

    #[test]
    fn crypt_parses_a_keyring_row() {
        let table: Crypt = "aes-xts-plain64 :64:logon:cryptsetup:abc-def-d0 0 7:0 32768"
            .parse()
            .expect("parse");
        assert_eq!(
            table.key,
            Key::Keyring {
                size: 64,
                kind: KeyType::Logon,
                description: "cryptsetup:abc-def-d0".to_owned(),
            }
        );
        assert_eq!(table.offset, 32768);
    }

    #[test]
    fn crypt_debug_never_reveals_key_bytes() {
        // The whole point of the keyring form is that key material does not
        // leak; a Debug print of a raw key must not undo that.
        let secret = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let rendered = format!(
            "{:?}",
            Crypt::new("aes-xts-plain64", Key::Hex(secret.to_vec()), dev())
        );
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("deadbeef"), "{rendered}");
        assert!(
            !rendered.contains("222"),
            "no decimal byte values: {rendered}"
        );
        // Display, by contrast, IS the wire codec and must emit the key.
        assert_eq!(Key::Hex(secret.to_vec()).to_string(), "deadbeef");
    }

    #[test]
    fn crypt_from_str_rejects_rows_it_cannot_hold() {
        for line in [
            // count disagrees with the arguments
            "aes-xts-plain64 ab 0 7:0 0 2 allow_discards",
            "aes-xts-plain64 ab 0 7:0 0 1 allow_discards same_cpu_crypt",
            // unknown optional argument
            "aes-xts-plain64 ab 0 7:0 0 1 no_such_argument",
            // odd-length hex key
            "aes-xts-plain64 abc 0 7:0 0",
            // non-hex key
            "aes-xts-plain64 zz 0 7:0 0",
            // unknown keyring type
            "aes-xts-plain64 :64:bogus:desc 0 7:0 0",
            // keyring reference missing its description
            "aes-xts-plain64 :64:logon 0 7:0 0",
            // keyring size is not a number
            "aes-xts-plain64 :big:logon:desc 0 7:0 0",
        ] {
            assert!(line.parse::<Crypt>().is_err(), "{line}");
        }
    }
}
