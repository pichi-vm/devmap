// SPDX-License-Identifier: Apache-2.0

use std::io;
use tinyvec::ArrayVec;
mod algorithm;
mod hash_type;
pub use algorithm::Algorithm;
pub use hash_type::HashType;

/// Hashing choices, independent of storage geometry and Linux activation.
///
/// Defaults to format 1, SHA-256, and no salt. All salt storage is inline.
///
/// Formatting uses the endpoints' geometry and persists the hash output before
/// returning. Keep the returned root in independently trusted storage.
///
/// ```
/// # #[cfg(feature = "sha2")]
/// # fn main() -> std::io::Result<()> {
/// use std::io::{Cursor, Read};
/// use devmap_core::BlockSize;
/// use devmap_verity::{Options, Scheme,
///     traits::std::{Format as _, Open as _, Scale as _}};
///
/// let data = vec![0x5a; 8192];
/// let block_size = BlockSize::<512>::default().into();
/// let input = Cursor::new(&data).scale_to(block_size)?;
/// let output = Cursor::new(Vec::new()).scale_to(block_size)?;
/// let (hashes, root) = Scheme::default().format(input, output, [7; 16])?;
///
/// let mut volume = Options::default().open(Cursor::new(data), hashes, &root)?;
/// let mut first = [0; 16];
/// volume.read_exact(&mut first)?;
/// assert_eq!(first, [0x5a; 16]);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "sha2"))]
/// # fn main() {}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scheme {
    /// The hash-tree convention.
    pub hash_type: HashType,
    /// The algorithm, representable independently of enabled hash features.
    pub algorithm: Algorithm,
    /// At most 256 salt bytes.
    pub salt: ArrayVec<[u8; 256]>,
}

impl Default for Scheme {
    fn default() -> Self {
        Self {
            hash_type: HashType::Normal,
            algorithm: Algorithm::Sha256,
            salt: ArrayVec::default(),
        }
    }
}

impl Scheme {
    /// Selects the hash-tree convention.
    #[must_use]
    pub const fn with_hash_type(mut self, value: HashType) -> Self {
        self.hash_type = value;
        self
    }
    /// Selects the algorithm.
    #[must_use]
    pub const fn with_algorithm(mut self, value: Algorithm) -> Self {
        self.algorithm = value;
        self
    }
    /// Replaces the salt without allocating.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for more than 256 bytes.
    pub fn with_salt(mut self, value: &[u8]) -> io::Result<Self> {
        self.salt = ArrayVec::try_from(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "salt exceeds 256 bytes"))?;
        Ok(self)
    }
}
