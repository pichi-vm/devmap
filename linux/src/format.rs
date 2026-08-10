// SPDX-License-Identifier: Apache-2.0

//! Formatting a target's on-disk metadata before its first table load,
//! with no external tool.
//!
//! Most stateful targets format themselves. thin-pool, cache, and era
//! detect an all-zero metadata block and write a fresh superblock on the
//! first load; writecache does the same from a zero magic; a snapshot COW
//! device and a raid metadata device read as fresh once zeroed. For all
//! of these, "format" is just [`zero_metadata`] over the metadata device.
//!
//! dm-integrity is the exception — it needs a load, a read-back, and a
//! second load — so [`crate::targets::Integrity::format`] wraps that
//! sequence.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

/// The metadata block the self-formatting targets scan for zeroes: the
/// kernel reads a 4 KiB superblock block (thin/cache/era) or the first
/// sectors of the metadata device and treats all-zero as "unformatted".
/// Zeroing this many leading bytes is enough to trigger a self-format.
pub const METADATA_BLOCK_LEN: u64 = 4096;

/// Zero the first `bytes` of the metadata device at `path` so a
/// self-formatting target initialises it on the next table load.
///
/// Pass [`METADATA_BLOCK_LEN`]; it covers thin-pool, cache, era, and
/// writecache metadata devices, and marks a snapshot COW device or raid
/// metadata device fresh. A freshly-attached sparse loop device already
/// reads as zero, but a reused device may carry a stale superblock the
/// kernel would then reject — this makes the state explicit rather than
/// relying on the device happening to be blank.
///
/// The write is followed by an `fsync`, so on return the zeroes are
/// durable and the next table load sees them.
///
/// # Errors
///
/// The underlying `io::Error` if `path` can't be opened for writing or
/// the write/sync fails.
pub fn zero_metadata(path: impl AsRef<Path>, bytes: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    // Chunked so a caller passing a large `bytes` doesn't allocate it all
    // at once; the common case is a single 4 KiB block.
    let chunk = vec![0u8; METADATA_BLOCK_LEN as usize];
    let mut written = 0u64;
    while written < bytes {
        let n = (bytes - written).min(chunk.len() as u64) as usize;
        file.write_all_at(&chunk[..n], written)?;
        written += n as u64;
    }
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_metadata_clears_only_the_leading_bytes() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("devmap-zero-{}", std::process::id()));
        // A file that starts life full of 0xFF past the region we zero.
        std::fs::write(&path, vec![0xFFu8; 8192]).expect("seed file");

        zero_metadata(&path, METADATA_BLOCK_LEN).expect("zero_metadata");

        let contents = std::fs::read(&path).expect("read back");
        assert!(
            contents[..4096].iter().all(|&b| b == 0),
            "the leading block must be zeroed"
        );
        assert!(
            contents[4096..].iter().all(|&b| b == 0xFF),
            "bytes past the requested length must be untouched"
        );
        std::fs::remove_file(&path).ok();
    }
}
