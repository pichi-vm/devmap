// SPDX-License-Identifier: Apache-2.0

//! The `verity` (dm-verity) target: read-only transparent integrity
//! checking of a device against a Merkle tree of hashes.

use std::fmt::{self, Write as _};

use crate::DevId;
use crate::table::{RawInfo, Target};

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
    /// The salt (raw bytes).
    pub salt: Vec<u8>,
}
impl Target for Verity {
    const NAME: &'static str = "verity";
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
        write_hex_lower(f, &self.salt)
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
}
