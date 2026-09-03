// SPDX-License-Identifier: Apache-2.0

use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{HashType, Verified};

/// The 512-byte on-disk form of a dm-verity superblock.
///
/// This value may contain invalid fields. Convert it to [`crate::Verified`]
/// before using it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Unverified {
    pub(super) signature: [u8; 8],
    pub(super) version: U32,
    pub(super) hash_type: U32,
    pub(super) uuid: [u8; 16],
    pub(super) algorithm: [u8; 32],
    pub(super) data_block_size: U32,
    pub(super) hash_block_size: U32,
    pub(super) data_blocks: U64,
    pub(super) salt_size: U16,
    pub(super) salt_padding: [u8; 6],
    pub(super) salt: [u8; 256],
    pub(super) padding: [u8; 168],
}

impl Unverified {
    pub(super) const SIGNATURE: [u8; 8] = *b"verity\0\0";
}

impl Default for Unverified {
    fn default() -> Self {
        Self {
            signature: [0; 8],
            version: U32::new(0),
            hash_type: U32::new(0),
            uuid: [0; 16],
            algorithm: [0; 32],
            data_block_size: U32::new(0),
            hash_block_size: U32::new(0),
            data_blocks: U64::new(0),
            salt_size: U16::new(0),
            salt_padding: [0; 6],
            salt: [0; 256],
            padding: [0; 168],
        }
    }
}

impl AsRef<[u8]> for Unverified {
    fn as_ref(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }
}

impl AsMut<[u8]> for Unverified {
    fn as_mut(&mut self) -> &mut [u8] {
        IntoBytes::as_mut_bytes(self)
    }
}

impl From<Verified> for Unverified {
    fn from(superblock: Verified) -> Self {
        Self::from(&superblock)
    }
}

impl From<&Verified> for Unverified {
    fn from(superblock: &Verified) -> Self {
        let mut algorithm = [0; 32];
        let name = superblock.algorithm.as_ref().as_bytes();
        algorithm[..name.len()].copy_from_slice(name);

        Self {
            signature: Unverified::SIGNATURE,
            version: U32::new(1),
            hash_type: U32::new(match superblock.hash_type {
                HashType::ChromeOs => 0,
                HashType::Normal => 1,
            }),
            uuid: superblock.uuid,
            algorithm,
            data_block_size: U32::new(superblock.data_block_size),
            hash_block_size: U32::new(superblock.hash_block_size),
            data_blocks: U64::new(superblock.data_blocks.get()),
            salt_size: U16::new(superblock.salt_size),
            salt_padding: [0; 6],
            salt: superblock.salt,
            padding: [0; 168],
        }
    }
}

const _: () = assert!(size_of::<Unverified>() == 512);

const _: () = {
    use core::mem::offset_of;

    assert!(offset_of!(Unverified, signature) == 0);
    assert!(offset_of!(Unverified, version) == 8);
    assert!(offset_of!(Unverified, hash_type) == 12);
    assert!(offset_of!(Unverified, uuid) == 16);
    assert!(offset_of!(Unverified, algorithm) == 32);
    assert!(offset_of!(Unverified, data_block_size) == 64);
    assert!(offset_of!(Unverified, hash_block_size) == 68);
    assert!(offset_of!(Unverified, data_blocks) == 72);
    assert!(offset_of!(Unverified, salt_size) == 80);
    assert!(offset_of!(Unverified, salt_padding) == 82);
    assert!(offset_of!(Unverified, salt) == 88);
    assert!(offset_of!(Unverified, padding) == 344);
};
