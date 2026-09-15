// SPDX-License-Identifier: Apache-2.0

use core::fmt;
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
use std::io;

#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
use digest::DynDigest;

/// A dm-verity hash-tree compatibility profile.
///
/// This setting is independent of the hash [`crate::Algorithm`]. Use
/// [`HashType::Normal`] unless compatibility with a format-0 Chrome OS image
/// is required.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashType {
    /// Format 0, used by Chrome OS images.
    ChromeOs,

    /// Format 1, used by current dm-verity tooling.
    #[default]
    Normal,
}

#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
impl HashType {
    pub(crate) fn digest(
        self,
        hasher: &mut dyn DynDigest,
        salt: &[u8],
        block: &[u8],
        output: &mut [u8],
    ) -> io::Result<()> {
        match self {
            Self::ChromeOs => {
                hasher.update(block);
                hasher.update(salt);
            }
            Self::Normal => {
                hasher.update(salt);
                hasher.update(block);
            }
        }
        hasher.finalize_into_reset(output).map_err(|_| {
            io::Error::other("hash output buffer does not match the algorithm's digest size")
        })
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChromeOs => 0.fmt(f),
            Self::Normal => 1.fmt(f),
        }
    }
}
