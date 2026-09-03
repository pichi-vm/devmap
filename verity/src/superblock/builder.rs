// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU64;

use super::{Algorithm, HashType, Verified};

/// Builds a [`Verified`] superblock.
///
/// The defaults are SHA-256, [`HashType::Normal`], 4096-byte blocks, and no
/// salt. [`build`](Self::build) takes the UUID and data-block count.
#[must_use]
#[derive(Debug, Clone)]
pub struct Builder {
    hash_type: HashType,
    algorithm: Algorithm,
    data_block_size: u32,
    hash_block_size: u32,
    salt: [u8; 256],
    salt_size: u16,
}

impl Builder {
    pub(super) const fn new() -> Self {
        Self {
            hash_type: HashType::Normal,
            algorithm: Algorithm::Sha256,
            data_block_size: 4096,
            hash_block_size: 4096,
            salt: [0; 256],
            salt_size: 0,
        }
    }

    /// Sets the hash-tree format.
    pub const fn hash_type(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;
        self
    }

    /// Sets the hash algorithm.
    pub const fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the data-device block size in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the size is not a power of
    /// two from 512 bytes through 512 KiB.
    pub fn data_block_size(mut self, data_block_size: u32) -> io::Result<Self> {
        if (512..=512 * 1024).contains(&data_block_size) && data_block_size.is_power_of_two() {
            self.data_block_size = data_block_size;
            return Ok(self);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid verity block size",
        ))
    }

    /// Sets the hash-device block size in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the size is not a power of
    /// two from 512 bytes through 512 KiB.
    pub fn hash_block_size(mut self, hash_block_size: u32) -> io::Result<Self> {
        if (512..=512 * 1024).contains(&hash_block_size) && hash_block_size.is_power_of_two() {
            self.hash_block_size = hash_block_size;
            return Ok(self);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid verity block size",
        ))
    }

    /// Sets the hash salt.
    ///
    /// Use a new randomly generated salt for each persistent image.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `salt` is longer than 256
    /// bytes.
    pub fn salt(mut self, salt: &[u8]) -> io::Result<Self> {
        let salt_size = u16::try_from(salt.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "salt exceeds 256 bytes"))?;
        if usize::from(salt_size) > self.salt.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salt exceeds 256 bytes",
            ));
        }

        self.salt.fill(0);
        self.salt[..salt.len()].copy_from_slice(salt);
        self.salt_size = salt_size;
        Ok(self)
    }

    /// Builds the superblock for `data_blocks` using the given UUID.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] if the data size does not fit in
    /// `u64`.
    pub fn build(self, uuid: [u8; 16], data_blocks: NonZeroU64) -> io::Result<Verified> {
        data_blocks
            .get()
            .checked_mul(u64::from(self.data_block_size))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "verity layout overflows"))?;

        Ok(Verified {
            hash_type: self.hash_type,
            uuid,
            algorithm: self.algorithm,
            data_block_size: self.data_block_size,
            hash_block_size: self.hash_block_size,
            data_blocks,
            salt: self.salt,
            salt_size: self.salt_size,
        })
    }
}
