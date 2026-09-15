// SPDX-License-Identifier: Apache-2.0

//! The `crypt` (dm-crypt) target: transparent encryption of a block
//! device through the kernel crypto API.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use devmap_core::Target;
use devmap_core::parse::{DevId, Empty, Error};

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

impl FromStr for Key {
    type Err = Error;

    /// Parses `-`, a `:size:type:description` keyring reference, or hex bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] for malformed fields, unknown keyring types,
    /// empty key descriptions, or invalid hex. Hex input accepts either case;
    /// formatting uses lowercase. Parsed raw keys remain sensitive data.
    fn from_str(token: &str) -> Result<Self, Self::Err> {
        if token == "-" {
            return Ok(Key::Absent);
        }
        if let Some(rest) = token.strip_prefix(':') {
            // `<size>:<type>:<description>` — the description may itself contain
            // colons (cryptsetup uses `cryptsetup:<uuid>-d0`), so split only twice.
            let (size, rest) = rest.split_once(':').ok_or(Error)?;
            let (kind, description) = rest.split_once(':').ok_or(Error)?;
            if description.is_empty() {
                return Err(Error);
            }
            return Ok(Key::Keyring {
                size: size.parse()?,
                kind: kind.parse()?,
                description: description.to_owned(),
            });
        }
        if token.is_empty() || !token.is_ascii() || token.len() % 2 != 0 {
            return Err(Error);
        }
        (0..token.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&token[i..i + 2], 16).map_err(|_| Error))
            .collect::<Result<Vec<u8>, _>>()
            .map(Key::Hex)
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
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "logon" => Ok(KeyType::Logon),
            "user" => Ok(KeyType::User),
            "encrypted" => Ok(KeyType::Encrypted),
            "trusted" => Ok(KeyType::Trusted),
            _ => Err(Error),
        }
    }
}

/// Per-sector integrity metadata carried alongside the ciphertext, stored
/// by an underlying dm-integrity device.
///
/// Encoded as `tag_size:kind`, without the enclosing `integrity:` option name.
/// Parsing validates the `u32` tag size and preserves the kind verbatim for
/// the kernel to interpret, including any additional colons.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integrity {
    /// Metadata bytes per sector.
    pub tag_size: u32,
    /// `none` for a persistent IV only, `aead` for authenticated encryption.
    pub kind: String,
}

impl FromStr for Integrity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (tag_size, kind) = s.split_once(':').ok_or(Error)?;
        Ok(Self {
            tag_size: tag_size.parse()?,
            kind: kind.to_owned(),
        })
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.tag_size, self.kind)
    }
}

/// Transparent encryption of `device`. Build with [`CryptTarget::new`] and set
/// the optional fields directly; they render in the kernel's own argument
/// order, so a row read back from `DM_TABLE_STATUS` round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
// Mirrors dm-crypt's bare optional flags, which are independent booleans.
#[allow(clippy::struct_excessive_bools)]
pub struct CryptTarget {
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

impl CryptTarget {
    /// A mapping of `device` under `cipher` with `key`, starting at sector
    /// 0 with no IV offset and no optional features.
    #[must_use]
    pub fn new(cipher: impl Into<String>, key: Key, device: DevId) -> Self {
        CryptTarget {
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

impl Target for CryptTarget {
    const NAME: &'static str = "crypt";
    type Table = Self;
    // dm-crypt's STATUSTYPE_INFO writes an empty string — it reports no
    // runtime state at all.
    type Info = Empty;
}

impl fmt::Display for CryptTarget {
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
            args.push(format!("integrity:{integrity}"));
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

impl FromStr for CryptTarget {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let cipher = fields.next().ok_or(Error)?.to_owned();
        let key = fields.next().ok_or(Error)?.parse()?;
        let iv_offset = fields.next().ok_or(Error)?.parse()?;
        let device = fields.next().ok_or(Error)?.parse::<DevId>()?;
        let offset = fields.next().ok_or(Error)?.parse()?;

        let mut crypt = CryptTarget {
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
        let Some(count) = fields.next() else {
            return Ok(crypt);
        };

        // Every optional argument is a single token, either a bare flag or a
        // `key:value` pair, so the count is a token count.
        let count: usize = count.parse()?;
        for _ in 0..count {
            let arg = fields.next().ok_or(Error)?;
            match arg {
                "allow_discards" => crypt.allow_discards = true,
                "same_cpu_crypt" => crypt.same_cpu_crypt = true,
                "high_priority" => crypt.high_priority = true,
                "submit_from_crypt_cpus" => crypt.submit_from_crypt_cpus = true,
                "no_read_workqueue" => crypt.no_read_workqueue = true,
                "no_write_workqueue" => crypt.no_write_workqueue = true,
                "iv_large_sectors" => crypt.iv_large_sectors = true,
                _ => {
                    let (key, value) = arg.split_once(':').ok_or(Error)?;
                    match key {
                        "integrity" => {
                            crypt.integrity = Some(value.parse()?);
                        }
                        "sector_size" => {
                            crypt.sector_size = Some(value.parse()?);
                        }
                        "integrity_key_size" => {
                            crypt.integrity_key_size = Some(value.parse()?);
                        }
                        _ => return Err(Error),
                    }
                }
            }
        }
        if fields.next().is_some() {
            return Err(Error);
        }
        Ok(crypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: Target + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    fn dev() -> DevId {
        DevId::new(252, 1).unwrap()
    }

    fn crypt() -> CryptTarget {
        CryptTarget::new("aes-xts-plain64", Key::Hex(vec![0xAB; 32]), dev())
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
        let t = CryptTarget {
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
            CryptTarget {
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
            CryptTarget {
                key: Key::Absent,
                ..crypt()
            },
        ] {
            let rendered = t.to_string();
            assert_eq!(
                rendered.parse::<CryptTarget>().as_ref(),
                Ok(&t),
                "{rendered}"
            );
        }
    }

    #[test]
    fn crypt_parses_the_row_the_kernel_reported() {
        // Captured from a live dm-crypt device (key masked by dmsetup).
        let reported = format!("aes-xts-plain64 {} 0 7:0 0", "0".repeat(64));
        let table: CryptTarget = reported.parse().expect("parse");
        assert_eq!(table.cipher, "aes-xts-plain64");
        assert_eq!(table.key.size(), 32);
        assert_eq!(table.device, DevId::new(7, 0).unwrap());
        assert_eq!(table.to_string(), reported);
    }

    #[test]
    fn crypt_parses_a_keyring_row() {
        let table: CryptTarget = "aes-xts-plain64 :64:logon:cryptsetup:abc-def-d0 0 7:0 32768"
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
            CryptTarget::new("aes-xts-plain64", Key::Hex(secret.to_vec()), dev())
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
            assert!(line.parse::<CryptTarget>().is_err(), "{line}");
        }
    }
}
