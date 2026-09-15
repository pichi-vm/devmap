// SPDX-License-Identifier: Apache-2.0

use crate::{chunk_size::ChunkSize, layer::state::State};
use std::{io, num::NonZeroU32};

/// Computes storage requirements for a persistent snapshot COW store.
///
/// Size the storage before formatting it with [`crate::traits::std::Create::create`].
/// The `tokio` feature provides the same operation in `traits::tokio`.
#[derive(Debug, Clone)]
#[must_use]
pub struct Formatter {
    chunk_size: ChunkSize,
}

impl Formatter {
    /// Selects a chunk size in 512-byte sectors.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for a size outside the persistent format's range.
    pub fn new(chunk_size: NonZeroU32) -> io::Result<Self> {
        Ok(Self {
            chunk_size: ChunkSize::new(chunk_size)?,
        })
    }

    /// Returns the bytes needed to hold a change to every origin chunk.
    ///
    /// Includes metadata and a terminating metadata area when necessary.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for incompatible COW block size or arithmetic overflow.
    pub fn required_size(&self, origin_bytes: u64, cow_block_size: NonZeroU32) -> io::Result<u64> {
        let bytes = self.chunk_size.bytes();
        if bytes % u64::from(cow_block_size.get()) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size is incompatible with the COW block size",
            ));
        }
        State::required_chunks(origin_bytes.div_ceil(bytes), self.chunk_size.len())?
            .checked_mul(bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "COW size exceeds u64"))
    }
}
