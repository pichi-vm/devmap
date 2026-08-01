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
#[non_exhaustive]
pub struct Verity {
    data_dev: DevId,
    hash_dev: DevId,
    num_data_blocks: u64,
    algorithm: String,
    digest: Vec<u8>,
    salt: Vec<u8>,
}
impl Verity {
    /// Construct a [`Verity`]. Data/hash block size is locked to 4096
    /// and `hash_start_block` to 1 (see the type docs); `digest` and
    /// `salt` are raw bytes, hex-encoded on write.
    ///
    /// Value rules (non-empty `algorithm`/`digest`/`salt`, allowed
    /// characters, and so on) are enforced by the kernel when the table
    /// is loaded, which rejects bad values with `EINVAL`.
    #[must_use]
    pub fn new(
        data_dev: DevId,
        hash_dev: DevId,
        num_data_blocks: u64,
        algorithm: impl Into<String>,
        digest: Vec<u8>,
        salt: Vec<u8>,
    ) -> Self {
        Verity {
            data_dev,
            hash_dev,
            num_data_blocks,
            algorithm: algorithm.into(),
            digest,
            salt,
        }
    }

    /// The data device.
    #[must_use]
    pub fn data_dev(&self) -> DevId {
        self.data_dev
    }
    /// The hash device.
    #[must_use]
    pub fn hash_dev(&self) -> DevId {
        self.hash_dev
    }
    /// Number of data blocks.
    #[must_use]
    pub fn num_data_blocks(&self) -> u64 {
        self.num_data_blocks
    }
    /// The hash algorithm name.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    /// The root digest (raw bytes).
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
    /// The salt (raw bytes).
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}
impl Target for Verity {
    const TYPE_NAME: &'static str = "verity";
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
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn verity_renders_per_kernel_docs() {
        let t = Verity::new(
            DevId::new(252, 100),
            DevId::new(252, 101),
            10,
            "sha256",
            vec![0xBB; 32],
            vec![0xAA; 32],
        );
        let rendered = line(0, 80, &t);
        assert!(rendered.contains("verity 1 252:100 252:101 4096 4096 10 1 sha256"));
        let toks: Vec<&str> = rendered.split_whitespace().collect();
        assert_eq!(*toks.last().unwrap(), "aa".repeat(32));
        assert_eq!(toks[toks.len() - 2], "bb".repeat(32));
    }
}
