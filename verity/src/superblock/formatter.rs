// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use super::{Algorithm, HashType, Header, layout::Layout};

/// Configures and formats a dm-verity hash device.
///
/// The defaults are SHA-256, [`HashType::Normal`], and no salt. The data and
/// hash block sizes and the protected extent are obtained from the endpoints
/// when `format` is called.
///
/// Import [`crate::traits::std::Format`] or, with the `tokio` feature,
/// [`crate::traits::tokio::Format`] to finish configuration with `format`.
#[must_use = "a formatter performs no I/O until `.format()` is called"]
#[derive(Debug, Clone)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "ripemd",
        feature = "whirlpool",
        feature = "streebog",
        feature = "sm3",
        feature = "blake2"
    )))
)]
pub struct Formatter {
    hash_type: HashType,
    algorithm: Algorithm,
    uuid: [u8; 16],
    salt: [u8; 256],
    salt_size: u16,
}

impl Formatter {
    /// Creates a formatter with the UUID written to the dm-verity superblock.
    ///
    /// The UUID is metadata, not a substitute for keeping the root digest
    /// returned by formatting in trusted storage.
    pub const fn new(uuid: [u8; 16]) -> Self {
        Self {
            hash_type: HashType::Normal,
            algorithm: Algorithm::Sha256,
            uuid,
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
    ///
    /// The matching Cargo feature must be enabled when [`Format::format`] is
    /// called. See [`crate::Algorithm`] for the feature associated with each
    /// family.
    ///
    /// [`Format::format`]: crate::traits::std::Format::format
    pub const fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Sets the hash salt bytes stored in the superblock and used for hashing.
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

    pub(crate) fn superblock(
        &self,
        data_size: u64,
        data_block_size: NonZeroU32,
        hash_block_size: NonZeroU32,
    ) -> io::Result<Header> {
        if data_size % u64::from(data_block_size.get()) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verity data size is not a whole number of data blocks",
            ));
        }
        let data_blocks = NonZeroU64::new(data_size / u64::from(data_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "verity data is empty"))?;
        let layout = Layout::new(
            data_blocks,
            data_block_size,
            hash_block_size,
            self.hash_type,
            self.algorithm,
        )?;
        Ok(Header {
            hash_type: self.hash_type,
            uuid: self.uuid,
            algorithm: self.algorithm,
            layout,
            salt: self.salt,
            salt_size: self.salt_size,
        })
    }
}
