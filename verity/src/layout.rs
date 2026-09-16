// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU32;

use crate::{HashType, Scheme, Shape};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Layout {
    pub(crate) scheme: Scheme,
    pub(crate) shape: Shape,
    pub(crate) data_size: u128,
    pub(crate) hashes_per_block: usize,
    pub(crate) slot_size: usize,
    pub(crate) level_offsets: Vec<u128>,
    pub(crate) tree_size: u128,
    pub(crate) hash_size: u128,
}

impl Layout {
    pub(crate) fn new(scheme: &Scheme, shape: Shape) -> io::Result<Self> {
        let data_blocks = shape.data_blocks;
        let data_block_size = NonZeroU32::from(shape.data_block_size);
        let hash_block_size = NonZeroU32::from(shape.hash_block_size);
        let hash_type = scheme.hash_type;
        let algorithm = scheme.algorithm;
        let overflow = || io::Error::new(io::ErrorKind::InvalidInput, "verity layout overflows");
        // Kernel extents count sectors; header-based I/O must also fit in u64 bytes.
        let data_size = u128::from(data_blocks.get()) * u128::from(data_block_size.get());
        if data_size / 512 > u128::from(u64::MAX) {
            return Err(overflow());
        }
        let digest_size = algorithm.digest_size();
        let capacity = hash_block_size.get() as usize / digest_size;
        if capacity < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hash block cannot hold two digests",
            ));
        }
        let hashes_per_block = 1usize << capacity.ilog2();
        let slot_size = match hash_type {
            HashType::ChromeOs => digest_size,
            HashType::Normal => digest_size.next_power_of_two(),
        };
        let mut level_blocks = Vec::new();
        let mut blocks = data_blocks.get();
        while blocks > 1 {
            blocks = blocks.div_ceil(hashes_per_block as u64);
            level_blocks.push(blocks);
        }
        let mut level_offsets = vec![0; level_blocks.len()];
        let mut tree_size = 0u128;
        for index in (0..level_blocks.len()).rev() {
            level_offsets[index] = tree_size;
            tree_size += u128::from(level_blocks[index]) * u128::from(hash_block_size.get());
        }
        let hash_size = tree_size + u128::from(hash_block_size.get());
        if tree_size / 512 > u128::from(u64::MAX) {
            return Err(overflow());
        }
        Ok(Self {
            scheme: *scheme,
            shape,
            data_size,
            hashes_per_block,
            slot_size,
            level_offsets,
            tree_size,
            hash_size,
        })
    }
    pub(crate) fn validate_header(&self) -> io::Result<()> {
        if self.data_size > u128::from(u64::MAX) || self.hash_size > u128::from(u64::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verity layout exceeds byte-addressable storage",
            ));
        }
        if u32::from(self.shape.data_block_size) > 512 * 1024
            || u32::from(self.shape.hash_block_size) > 512 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verity header block size",
            ));
        }
        Ok(())
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
impl Layout {
    pub(crate) fn data_block_size(&self) -> NonZeroU32 {
        self.shape.data_block_size.into()
    }
    pub(crate) fn hash_block_size(&self) -> NonZeroU32 {
        self.shape.hash_block_size.into()
    }
    pub(crate) const fn data_blocks(&self) -> std::num::NonZeroU64 {
        self.shape.data_blocks
    }
    pub(crate) const fn hash_type(&self) -> HashType {
        self.scheme.hash_type
    }
    pub(crate) const fn algorithm(&self) -> crate::Algorithm {
        self.scheme.algorithm
    }
    pub(crate) fn salt(&self) -> &[u8] {
        self.scheme.salt.as_slice()
    }
}
