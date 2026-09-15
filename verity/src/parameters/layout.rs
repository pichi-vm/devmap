// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use super::{Algorithm, HashType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Layout {
    pub(crate) data_blocks: NonZeroU64,
    pub(crate) data_block_size: NonZeroU32,
    pub(crate) hash_block_size: NonZeroU32,
    pub(crate) data_size: u128,
    pub(crate) hashes_per_block: usize,
    pub(crate) slot_size: usize,
    pub(crate) level_offsets: Vec<u128>,
    pub(crate) tree_size: u128,
    pub(crate) hash_size: u128,
}

impl Layout {
    pub(super) fn new(
        data_blocks: NonZeroU64,
        data_block_size: NonZeroU32,
        hash_block_size: NonZeroU32,
        hash_type: HashType,
        algorithm: Algorithm,
    ) -> io::Result<Self> {
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
            data_blocks,
            data_block_size,
            hash_block_size,
            data_size,
            hashes_per_block,
            slot_size,
            level_offsets,
            tree_size,
            hash_size,
        })
    }
}
