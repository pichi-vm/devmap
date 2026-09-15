// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use super::{Algorithm, HashType, Unverified, layout::Layout};

/// Validated metadata describing a dm-verity hash device.
///
/// Obtained from [`crate::Hashes::header`]. Validation covers the record's
/// fields and layout arithmetic, not the contents or capacity of its backing
/// devices. The header contains no trusted root digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Header {
    pub(super) hash_type: HashType,
    pub(super) uuid: [u8; 16],
    pub(super) algorithm: Algorithm,
    pub(super) salt: [u8; 256],
    pub(super) salt_size: u16,
    pub(crate) layout: Layout,
}

impl Header {
    pub(crate) fn from_parts(
        uuid: [u8; 16],
        hash_type: HashType,
        algorithm: Algorithm,
        data_block_size: NonZeroU32,
        hash_block_size: NonZeroU32,
        data_blocks: NonZeroU64,
        salt_bytes: &[u8],
    ) -> io::Result<Self> {
        if salt_bytes.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "salt exceeds 256 bytes",
            ));
        }
        let layout = Layout::new(
            data_blocks,
            data_block_size,
            hash_block_size,
            hash_type,
            algorithm,
        )?;
        let mut salt = [0; 256];
        salt[..salt_bytes.len()].copy_from_slice(salt_bytes);
        let salt_size = u16::try_from(salt_bytes.len())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            hash_type,
            uuid,
            algorithm,
            salt,
            salt_size,
            layout,
        })
    }

    /// Returns the volume UUID stored in the superblock.
    pub const fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Returns the hash-tree format.
    pub const fn hash_type(&self) -> HashType {
        self.hash_type
    }

    /// Returns the named algorithm, independently of enabled hashing features.
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

    /// Returns the salt bytes used when hashing data and tree blocks.
    pub fn salt(&self) -> &[u8] {
        &self.salt[..usize::from(self.salt_size)]
    }
}

impl TryFrom<&Unverified> for Header {
    type Error = io::Error;

    fn try_from(encoded: &Unverified) -> io::Result<Self> {
        let bytes = encoded.as_ref();
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
        if bytes[..Unverified::VERSION] != Unverified::SIGNATURE {
            return Err(invalid("invalid verity signature"));
        }
        if u32::from_le_bytes(encoded.field(Unverified::VERSION)) != 1 {
            return Err(invalid("unsupported verity version"));
        }
        let hash_type = match u32::from_le_bytes(encoded.field(Unverified::HASH_TYPE)) {
            0 => HashType::ChromeOs,
            1 => HashType::Normal,
            _ => return Err(invalid("unsupported verity hash type")),
        };
        let name = &bytes[Unverified::ALGORITHM..Unverified::DATA_BLOCK_SIZE];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        if name[end..].iter().any(|byte| *byte != 0) {
            return Err(invalid("invalid hash algorithm encoding"));
        }
        let algorithm = std::str::from_utf8(&name[..end])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .parse()?;
        let data_blocks =
            NonZeroU64::new(u64::from_le_bytes(encoded.field(Unverified::DATA_BLOCKS)))
                .ok_or_else(|| invalid("verity data block count must be nonzero"))?;
        let data_block_size = NonZeroU32::new(u32::from_le_bytes(
            encoded.field(Unverified::DATA_BLOCK_SIZE),
        ))
        .ok_or_else(|| invalid("invalid verity data block size"))?;
        let hash_block_size = NonZeroU32::new(u32::from_le_bytes(
            encoded.field(Unverified::HASH_BLOCK_SIZE),
        ))
        .ok_or_else(|| invalid("invalid verity hash block size"))?;
        let salt_size = u16::from_le_bytes(encoded.field(Unverified::SALT_SIZE));
        if salt_size > 256 {
            return Err(invalid("salt exceeds 256 bytes"));
        }
        if bytes[Unverified::SALT_PADDING..Unverified::SALT]
            .iter()
            .chain(&bytes[Unverified::SALT + usize::from(salt_size)..Unverified::PADDING])
            .any(|byte| *byte != 0)
        {
            return Err(invalid("nonzero salt padding"));
        }
        if bytes[Unverified::PADDING..].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero verity superblock padding"));
        }
        let layout = Layout::new(
            data_blocks,
            data_block_size,
            hash_block_size,
            hash_type,
            algorithm,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Self {
            hash_type,
            uuid: encoded.field(Unverified::UUID),
            algorithm,
            salt: encoded.field(Unverified::SALT),
            salt_size,
            layout,
        })
    }
}
