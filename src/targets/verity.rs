// SPDX-License-Identifier: Apache-2.0

//! The `verity` (dm-verity) target: read-only transparent integrity
//! checking of a device against a Merkle tree of hashes.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

// Data/hash block size for `Verity`, locked to 4096 rather than exposing
// every value the kernel target supports.
const VERITY_BLOCK_SIZE: u32 = 4096;

/// Write `bytes` as lowercase hex, two chars per byte.
fn write_hex_lower<W: fmt::Write + ?Sized>(w: &mut W, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(w, "{b:02x}")?;
    }
    Ok(())
}

/// Write a salt as lowercase hex, or `-` when it is empty.
///
/// dm-verity documents `<salt>` as "Hex string or `-` if no salt" and its
/// status emits `-` for a zero-length salt. Rendering nothing would leave
/// the table one argument short, which the kernel rejects.
fn write_salt<W: fmt::Write + ?Sized>(w: &mut W, salt: &[u8]) -> fmt::Result {
    if salt.is_empty() {
        w.write_str("-")
    } else {
        write_hex_lower(w, salt)
    }
}

/// Decode a lowercase-hex token. The kernel writes `-` for an empty salt.
fn parse_hex(s: &str) -> Result<Vec<u8>, ParseError> {
    if s == "-" {
        return Ok(Vec::new());
    }
    if !s.len().is_multiple_of(2) {
        return Err(ParseError);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ParseError))
        .collect()
}

/// A dm-verity mapping. `digest` and `salt` are raw bytes, hex-encoded on
/// write. The data and hash block sizes are locked to 4096 bytes and
/// `hash_start_block` to 1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verity {
    /// The data device.
    pub data_dev: DevId,
    /// The hash device.
    pub hash_dev: DevId,
    /// Number of data blocks.
    pub num_data_blocks: u64,
    /// The hash algorithm name.
    ///
    /// Value rules (non-empty algorithm/digest/salt, allowed characters,
    /// and so on) are enforced by the kernel on table load, which rejects
    /// bad values with `EINVAL`.
    pub algorithm: String,
    /// The root digest (raw bytes).
    pub digest: Vec<u8>,
    /// The salt (raw bytes). Empty renders as the kernel's `-` sentinel.
    pub salt: Vec<u8>,
}
impl Target for Verity {
    const NAME: &'static str = "verity";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Verity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let block_size = VERITY_BLOCK_SIZE;
        write!(
            f,
            "1 {} {} {block_size} {block_size} {} 1 {} ",
            self.data_dev, self.hash_dev, self.num_data_blocks, self.algorithm,
        )?;
        write_hex_lower(f, &self.digest)?;
        f.write_char(' ')?;
        write_salt(f, &self.salt)
    }
}
impl FromStr for Verity {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        // This type locks the version, both block sizes, and the hash
        // start block. A row carrying anything else is a valid dm-verity
        // table it cannot hold, so check rather than assume: silently
        // reporting a 512-byte-block mapping as 4096 would be a misread.
        if p.value::<u32>()? != 1 {
            return Err(ParseError);
        }
        let data_dev = p.device()?;
        let hash_dev = p.device()?;
        if p.value::<u32>()? != VERITY_BLOCK_SIZE || p.value::<u32>()? != VERITY_BLOCK_SIZE {
            return Err(ParseError);
        }
        let num_data_blocks = p.value()?;
        if p.value::<u64>()? != 1 {
            return Err(ParseError);
        }
        let algorithm = p.token()?.to_owned();
        let digest = parse_hex(p.token()?)?;
        let salt = parse_hex(p.token()?)?;
        // Trailing tokens are dm-verity's optional arguments (error
        // handling mode, FEC, signature key), none of which this type
        // renders.
        p.end()?;
        Ok(Verity {
            data_dev,
            hash_dev,
            num_data_blocks,
            algorithm,
            digest,
            salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {params}", T::NAME)
        }
    }

    #[test]
    fn verity_renders_per_kernel_docs() {
        let t = Verity {
            data_dev: DevId::new(252, 100).unwrap(),
            hash_dev: DevId::new(252, 101).unwrap(),
            num_data_blocks: 10,
            algorithm: "sha256".to_owned(),
            digest: vec![0xBB; 32],
            salt: vec![0xAA; 32],
        };
        let rendered = line(0, 80, &t);
        assert!(rendered.contains("verity 1 252:100 252:101 4096 4096 10 1 sha256"));
        let toks: Vec<&str> = rendered.split_whitespace().collect();
        assert_eq!(*toks.last().unwrap(), "aa".repeat(32));
        assert_eq!(toks[toks.len() - 2], "bb".repeat(32));
    }

    fn verity() -> Verity {
        Verity {
            data_dev: DevId::new(252, 100).unwrap(),
            hash_dev: DevId::new(252, 101).unwrap(),
            num_data_blocks: 4096,
            algorithm: "sha256".to_owned(),
            digest: vec![0xBB; 32],
            salt: vec![0xAA; 32],
        }
    }

    #[test]
    fn verity_display_from_str_round_trips() {
        let original = verity();
        assert_eq!(
            original.to_string().parse::<Verity>().as_ref(),
            Ok(&original)
        );
    }

    #[test]
    fn verity_renders_an_empty_salt_as_the_kernel_sentinel() {
        let original = Verity {
            salt: Vec::new(),
            ..verity()
        };
        // Ten arguments, the last of them "-". Rendering the empty salt as
        // nothing would leave nine and the kernel would reject the table.
        let rendered = original.to_string();
        assert_eq!(rendered.split_whitespace().count(), 10);
        assert!(rendered.ends_with(" -"));
        assert_eq!(rendered.parse::<Verity>().as_ref(), Ok(&original));
    }

    #[test]
    fn verity_from_str_rejects_rows_outside_its_locked_fields() {
        let good = verity().to_string();
        let field = |i: usize, v: &str| {
            let mut toks: Vec<&str> = good.split_whitespace().collect();
            toks[i] = v;
            toks.join(" ")
        };
        // version, data block size, hash block size, hash start block
        for (i, v) in [(0, "0"), (3, "512"), (4, "512"), (6, "0")] {
            let line = field(i, v);
            assert!(line.parse::<Verity>().is_err(), "{line}");
        }
        // dm-verity's optional-argument tail
        let line = format!("{good} 2 restart_on_corruption ignore_zero_blocks");
        assert!(line.parse::<Verity>().is_err());
    }

    #[test]
    fn verity_from_str_rejects_malformed_hex() {
        let good = verity().to_string();
        assert!(good.replace("bb", "zz").parse::<Verity>().is_err());
        assert!(
            good.replacen(&"bb".repeat(32), "abc", 1)
                .parse::<Verity>()
                .is_err()
        );
    }
}
