// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU64;

use super::{Algorithm, Builder, HashType, Unverified};

/// A validated dm-verity superblock.
///
/// Use [`builder`](Self::builder) to create one. Validate a value read from disk
/// by converting it from [`Unverified`]. Convert this value to [`Unverified`]
/// before writing it.
///
/// Conversion from [`Unverified`] checks the signature, version, hash format,
/// algorithm name, block sizes, data-block count, salt length, reserved bytes,
/// and layout size. Reserved bytes and unused bytes in fixed-size fields must
/// be zero.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verified {
    pub(super) hash_type: HashType,
    pub(super) uuid: [u8; 16],
    pub(super) algorithm: Algorithm,
    pub(super) data_block_size: u32,
    pub(super) hash_block_size: u32,
    pub(super) data_blocks: NonZeroU64,
    pub(super) salt: [u8; 256],
    pub(super) salt_size: u16,
}

impl Verified {
    /// Returns a superblock builder.
    ///
    /// Use a new UUID and salt for each persistent image.
    pub const fn builder() -> Builder {
        Builder::new()
    }

    /// Returns the padding between the 512-byte superblock and the hash tree.
    #[must_use]
    pub const fn padding(&self) -> u64 {
        self.hash_block_size() as u64 - size_of::<Unverified>() as u64
    }

    /// Returns the hash-tree format.
    #[must_use]
    pub const fn hash_type(&self) -> HashType {
        self.hash_type
    }

    /// Returns the 16-byte UUID.
    #[must_use]
    pub const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Returns the hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the data-device block size in bytes.
    #[must_use]
    pub const fn data_block_size(&self) -> u32 {
        self.data_block_size
    }

    /// Returns the hash-device block size in bytes.
    #[must_use]
    pub const fn hash_block_size(&self) -> u32 {
        self.hash_block_size
    }

    /// Returns the number of data blocks covered by the tree.
    #[must_use]
    pub const fn data_blocks(&self) -> NonZeroU64 {
        self.data_blocks
    }

    /// Returns the hash salt.
    #[must_use]
    pub const fn salt(&self) -> &[u8] {
        self.salt.split_at(self.salt_size as usize).0
    }
}

impl TryFrom<Unverified> for Verified {
    type Error = io::Error;

    #[allow(clippy::large_types_passed_by_value)]
    fn try_from(bytes: Unverified) -> io::Result<Self> {
        if bytes.signature != Unverified::SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid verity signature",
            ));
        }

        if bytes.version.get() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported verity version",
            ));
        }

        let hash_type = match bytes.hash_type.get() {
            0 => HashType::ChromeOs,
            1 => HashType::Normal,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported verity hash type",
                ));
            }
        };

        let algorithm_end = bytes
            .algorithm
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.algorithm.len());

        if bytes.algorithm[algorithm_end..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hash algorithm encoding",
            ));
        }

        let algorithm = core::str::from_utf8(&bytes.algorithm[..algorithm_end])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .parse()?;

        let data_blocks = NonZeroU64::new(bytes.data_blocks.get()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "verity data block count must be nonzero",
            )
        })?;

        let salt_size = usize::from(bytes.salt_size.get());
        let salt_bytes = bytes
            .salt
            .get(..salt_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "salt exceeds 256 bytes"))?;

        if bytes.salt_padding != [0; 6] || bytes.salt[salt_size..].iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nonzero salt padding",
            ));
        }

        if bytes.padding.iter().any(|byte| *byte != 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "nonzero verity superblock padding",
            ));
        }

        Self::builder()
            .algorithm(algorithm)
            .hash_type(hash_type)
            .data_block_size(bytes.data_block_size.get())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .hash_block_size(bytes.hash_block_size.get())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .salt(salt_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .build(bytes.uuid, data_blocks)
    }
}
