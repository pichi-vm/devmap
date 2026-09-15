// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use super::{Algorithm, HashType};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Layout {
    pub(crate) data_blocks: NonZeroU64,
    pub(crate) data_block_size: NonZeroU32,
    pub(crate) hash_block_size: NonZeroU32,
    pub(crate) data_size: u64,
    pub(crate) hashes_per_block: usize,
    pub(crate) slot_size: usize,
    pub(crate) level_offsets: Vec<u64>,
    pub(crate) tree_size: u64,
    pub(crate) hash_size: u64,
}

impl Layout {
    pub(super) fn new(
        data_blocks: NonZeroU64,
        data_block_size: NonZeroU32,
        hash_block_size: NonZeroU32,
        hash_type: HashType,
        algorithm: Algorithm,
    ) -> io::Result<Self> {
        for size in [data_block_size.get(), hash_block_size.get()] {
            if !(512..=512 * 1024).contains(&size) || !size.is_power_of_two() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid verity block size",
                ));
            }
        }
        let overflow = || io::Error::new(io::ErrorKind::InvalidInput, "verity layout overflows");
        let data_size = data_blocks
            .get()
            .checked_mul(u64::from(data_block_size.get()))
            .ok_or_else(overflow)?;
        let digest_size = algorithm.digest_size();
        let capacity = hash_block_size.get() as usize / digest_size;
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
        let mut tree_size = 0u64;
        for index in (0..level_blocks.len()).rev() {
            level_offsets[index] = tree_size;
            let size = level_blocks[index]
                .checked_mul(u64::from(hash_block_size.get()))
                .ok_or_else(overflow)?;
            tree_size = tree_size.checked_add(size).ok_or_else(overflow)?;
        }
        let hash_size = tree_size
            .checked_add(u64::from(hash_block_size.get()))
            .ok_or_else(overflow)?;
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
