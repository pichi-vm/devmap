// SPDX-License-Identifier: Apache-2.0

use std::num::{NonZeroU32, NonZeroU64};

mod algorithm;
mod builder;
mod hash_type;
mod layout;

pub use algorithm::Algorithm;
pub use builder::Builder;
pub use hash_type::HashType;

/// Shared hashing parameters for a verity tree and its Linux target.
///
/// Construct with [`Self::builder`] or borrow from [`crate::Hashes::parameters`].
/// Parameters contain neither a UUID nor a trusted root digest.
///
/// ```
/// # #[cfg(feature = "sha2")]
/// # fn main() -> std::io::Result<()> {
/// use std::{io::{Cursor, Read}, num::NonZeroU64};
/// use devmap_verity::{Parameters, Verity, traits::std::{Format as _, Open as _}};
///
/// let data = vec![0x5a; 8192];
/// let parameters = Parameters::builder().build(NonZeroU64::new(2).unwrap())?;
/// let (hashes, root) = parameters.format(
///     Cursor::new(&data), Cursor::new(Vec::new()), [7; 16],
/// )?;
/// let mut volume = Verity::open(Cursor::new(data), hashes, &root)?;
/// let mut first = [0; 16];
/// volume.read_exact(&mut first)?;
/// assert_eq!(first, [0x5a; 16]);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "sha2"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parameters {
    hash_type: HashType,
    algorithm: Algorithm,
    salt: Vec<u8>,
    pub(crate) layout: layout::Layout,
}

impl Parameters {
    /// Starts a builder with conventional defaults.
    pub const fn builder() -> Builder {
        Builder::new()
    }

    /// Returns the hash-tree format.
    pub const fn hash_type(&self) -> HashType {
        self.hash_type
    }

    /// Returns the algorithm, independently of enabled hashing features.
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the protected data-block size in bytes.
    pub const fn data_block_size(&self) -> NonZeroU32 {
        self.layout.data_block_size
    }

    /// Returns the hash-block size in bytes.
    pub const fn hash_block_size(&self) -> NonZeroU32 {
        self.layout.hash_block_size
    }

    /// Returns the number of protected data blocks.
    pub const fn data_blocks(&self) -> NonZeroU64 {
        self.layout.data_blocks
    }

    /// Returns the salt used when hashing data and tree blocks.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub(crate) fn validate_header(&self) -> std::io::Result<()> {
        if self.layout.data_size > u128::from(u64::MAX)
            || self.layout.hash_size > u128::from(u64::MAX)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "verity layout exceeds byte-addressable storage",
            ));
        }
        if self.salt.len() > 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "salt exceeds 256 bytes",
            ));
        }
        if self.data_block_size().get() > 512 * 1024 || self.hash_block_size().get() > 512 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid verity header block size",
            ));
        }
        Ok(())
    }
}
