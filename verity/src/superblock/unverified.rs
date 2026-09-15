// SPDX-License-Identifier: Apache-2.0

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
use crate::{HashType, Parameters};

/// The fixed-size record, excluding padding to the hash-block boundary.
#[derive(Debug)]
pub(crate) struct Unverified([u8; Self::LEN]);

impl Unverified {
    pub(super) const SIGNATURE: [u8; 8] = *b"verity\0\0";
    pub(super) const VERSION: usize = Self::SIGNATURE.len();
    pub(super) const HASH_TYPE: usize = Self::VERSION + 4;
    pub(super) const UUID: usize = Self::HASH_TYPE + 4;
    pub(super) const ALGORITHM: usize = Self::UUID + 16;
    pub(super) const DATA_BLOCK_SIZE: usize = Self::ALGORITHM + 32;
    pub(super) const HASH_BLOCK_SIZE: usize = Self::DATA_BLOCK_SIZE + 4;
    pub(super) const DATA_BLOCKS: usize = Self::HASH_BLOCK_SIZE + 4;
    pub(super) const SALT_SIZE: usize = Self::DATA_BLOCKS + 8;
    pub(super) const SALT_PADDING: usize = Self::SALT_SIZE + 2;
    pub(super) const SALT: usize = Self::SALT_PADDING + 6;
    pub(super) const PADDING: usize = Self::SALT + 256;
    const LEN: usize = Self::PADDING + 168;

    pub(super) fn field<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut field = [0; N];
        // All callers select fixed fields within this 512-byte record.
        field.copy_from_slice(&self.0[offset..offset + N]);
        field
    }
}

impl Default for Unverified {
    fn default() -> Self {
        Self([0; Self::LEN])
    }
}

impl AsRef<[u8]> for Unverified {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Unverified {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
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
impl TryFrom<(&Parameters, [u8; 16])> for Unverified {
    type Error = std::io::Error;

    fn try_from((parameters, uuid): (&Parameters, [u8; 16])) -> Result<Self, Self::Error> {
        parameters.validate_header()?;
        let mut encoded = Self::default();
        let bytes = &mut encoded.0;
        bytes[..Self::VERSION].copy_from_slice(&Self::SIGNATURE);
        bytes[Self::VERSION..Self::HASH_TYPE].copy_from_slice(&1u32.to_le_bytes());
        let hash_type: u32 = match parameters.hash_type() {
            HashType::ChromeOs => 0,
            HashType::Normal => 1,
        };
        bytes[Self::HASH_TYPE..Self::UUID].copy_from_slice(&hash_type.to_le_bytes());
        bytes[Self::UUID..Self::ALGORITHM].copy_from_slice(&uuid);
        let algorithm = parameters.algorithm();
        let name = algorithm.as_ref().as_bytes();
        bytes[Self::ALGORITHM..Self::ALGORITHM + name.len()].copy_from_slice(name);
        bytes[Self::DATA_BLOCK_SIZE..Self::HASH_BLOCK_SIZE]
            .copy_from_slice(&parameters.data_block_size().get().to_le_bytes());
        bytes[Self::HASH_BLOCK_SIZE..Self::DATA_BLOCKS]
            .copy_from_slice(&parameters.hash_block_size().get().to_le_bytes());
        bytes[Self::DATA_BLOCKS..Self::SALT_SIZE]
            .copy_from_slice(&parameters.data_blocks().get().to_le_bytes());
        bytes[Self::SALT_SIZE..Self::SALT_PADDING]
            .copy_from_slice(&(parameters.salt().len() as u16).to_le_bytes());
        bytes[Self::SALT..Self::SALT + parameters.salt().len()].copy_from_slice(parameters.salt());
        Ok(encoded)
    }
}

const _: () = {
    assert!(size_of::<Unverified>() == 512);
    assert!(Unverified::VERSION == 8);
    assert!(Unverified::HASH_TYPE == 12);
    assert!(Unverified::UUID == 16);
    assert!(Unverified::ALGORITHM == 32);
    assert!(Unverified::DATA_BLOCK_SIZE == 64);
    assert!(Unverified::HASH_BLOCK_SIZE == 68);
    assert!(Unverified::DATA_BLOCKS == 72);
    assert!(Unverified::SALT_SIZE == 80);
    assert!(Unverified::SALT_PADDING == 82);
    assert!(Unverified::SALT == 88);
    assert!(Unverified::PADDING == 344);
};
