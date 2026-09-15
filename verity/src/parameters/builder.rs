// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    num::{NonZeroU32, NonZeroU64},
};

use super::{Algorithm, HashType, Parameters, layout::Layout};

/// Builds shared hashing parameters for formatting or Linux activation.
///
/// Defaults to format 1, SHA-256, 4096-byte blocks, and no salt.
#[derive(Debug, Clone)]
#[must_use]
pub struct Builder {
    hash_type: HashType,
    algorithm: Algorithm,
    data_block_size: NonZeroU32,
    hash_block_size: NonZeroU32,
    salt: Vec<u8>,
}

impl Builder {
    pub(super) const fn new() -> Self {
        Self {
            hash_type: HashType::Normal,
            algorithm: Algorithm::Sha256,
            data_block_size: NonZeroU32::new(4096).unwrap(),
            hash_block_size: NonZeroU32::new(4096).unwrap(),
            salt: Vec::new(),
        }
    }

    /// Selects hash format 0 or 1.
    pub const fn hash_type(mut self, value: HashType) -> Self {
        self.hash_type = value;
        self
    }

    /// Selects the algorithm, independently of enabled hashing features.
    pub const fn algorithm(mut self, value: Algorithm) -> Self {
        self.algorithm = value;
        self
    }

    fn block_size(bytes: u32) -> io::Result<NonZeroU32> {
        if bytes < 512 || !bytes.is_power_of_two() || bytes > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verity block size",
            ));
        }
        NonZeroU32::new(bytes).ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// Sets the data-block size in bytes.
    ///
    /// # Errors
    ///
    /// Rejects sizes that are not powers of two in `512..=2^30`.
    pub fn data_block_size(mut self, bytes: u32) -> io::Result<Self> {
        self.data_block_size = Self::block_size(bytes)?;
        Ok(self)
    }

    /// Sets the hash-block size in bytes.
    ///
    /// # Errors
    ///
    /// Rejects sizes that are not powers of two in `512..=2^30`.
    pub fn hash_block_size(mut self, bytes: u32) -> io::Result<Self> {
        self.hash_block_size = Self::block_size(bytes)?;
        Ok(self)
    }

    /// Sets salt bytes; only header-based operations impose a 256-byte limit.
    pub fn salt(mut self, salt: &[u8]) -> Self {
        self.salt = salt.into();
        self
    }

    /// Builds parameters protecting `data_blocks` complete data blocks.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the layout exceeds `u64` sector addressing.
    pub fn build(self, data_blocks: NonZeroU64) -> io::Result<Parameters> {
        let layout = Layout::new(
            data_blocks,
            self.data_block_size,
            self.hash_block_size,
            self.hash_type,
            self.algorithm,
        )?;
        Ok(Parameters {
            hash_type: self.hash_type,
            algorithm: self.algorithm,
            salt: self.salt,
            layout,
        })
    }
}
