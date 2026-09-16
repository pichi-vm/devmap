// SPDX-License-Identifier: Apache-2.0

use super::Hashes;
use crate::layout::Layout;
use digest::DynDigest;
use std::{fmt, io};

#[cfg(feature = "tokio")]
mod r#async;
mod sync;
#[cfg(all(test, feature = "sha2"))]
mod tests;

/// Distinguishes a detected hash mismatch from transport errors with InvalidData.
#[derive(Debug)]
pub(crate) struct Mismatch;
impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("verity authentication failed")
    }
}
impl std::error::Error for Mismatch {}

pub(super) struct State {
    hasher: Box<dyn DynDigest + Send + Sync>,
    expected: Box<[u8]>,
    actual: Box<[u8]>,
    block: Box<[u8]>,
    #[cfg(feature = "tokio")]
    phase: r#async::Phase,
}

impl State {
    fn new(layout: &Layout) -> io::Result<Self> {
        let hasher = layout.algorithm().hasher().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "hash algorithm support is not enabled",
            )
        })?;
        let size = layout.algorithm().digest_size();
        Ok(Self {
            hasher,
            expected: vec![0; size].into_boxed_slice(),
            actual: vec![0; size].into_boxed_slice(),
            block: vec![0; layout.hash_block_size().get() as usize].into_boxed_slice(),
            #[cfg(feature = "tokio")]
            phase: r#async::Phase::Idle,
        })
    }

    fn begin(&mut self, layout: &Layout, index: u64, root: &[u8]) -> io::Result<()> {
        if index >= layout.data_blocks().get() || root.len() != self.expected.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verity lookup",
            ));
        }
        // Reset the trust anchor on every operation, even when storage is unchanged.
        self.expected.copy_from_slice(root);
        Ok(())
    }

    fn child(layout: &Layout, level: usize, mut index: u64) -> u64 {
        for _ in 0..level {
            index /= layout.hashes_per_block as u64;
        }
        index
    }

    fn offset(layout: &Layout, level: usize, index: u64) -> u64 {
        // Header validation bounds the complete tree; begin bounds the index.
        u64::from(layout.hash_block_size().get())
            + layout.level_offsets[level] as u64
            + Self::child(layout, level, index) / layout.hashes_per_block as u64
                * u64::from(layout.hash_block_size().get())
    }

    fn advance(&mut self, layout: &Layout, level: usize, index: u64) -> io::Result<()> {
        layout.hash_type().digest(
            self.hasher.as_mut(),
            layout.salt(),
            &self.block,
            &mut self.actual,
        )?;
        if self.actual != self.expected {
            return Err(io::Error::new(io::ErrorKind::InvalidData, Mismatch));
        }
        let slot = (Self::child(layout, level, index) % layout.hashes_per_block as u64) as usize;
        let start = slot * layout.slot_size;
        let size = self.expected.len();
        self.expected
            .copy_from_slice(&self.block[start..start + size]);
        Ok(())
    }
}

impl<H> Hashes<H> {
    fn validate_geometry(&self, block_size: std::num::NonZeroU32, count: u64) -> io::Result<()> {
        let bytes = count
            .checked_mul(u64::from(block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "hash geometry overflows"))?;
        if self.layout.hash_block_size().get() % block_size.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity hash block size is incompatible with the endpoint block size",
            ));
        }
        if u128::from(bytes) < self.layout.hash_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hash endpoint is shorter than the declared layout",
            ));
        }
        Ok(())
    }
}
