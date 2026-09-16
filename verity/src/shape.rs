// SPDX-License-Identifier: Apache-2.0

use crate::BlockSize;
use std::num::NonZeroU64;

/// Editable block geometry, independent of hashing choices.
///
/// Field values are valid individually; consumers check the complete extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Shape {
    /// Size of each protected data block.
    pub data_block_size: BlockSize,
    /// Size of each hash-tree block.
    pub hash_block_size: BlockSize,
    /// Number of protected data blocks.
    pub data_blocks: NonZeroU64,
}

impl Shape {
    /// Describes `data_blocks` blocks using 4096-byte data and hash blocks.
    pub fn new(data_blocks: NonZeroU64) -> Self {
        Self {
            data_block_size: BlockSize::default(),
            hash_block_size: BlockSize::default(),
            data_blocks,
        }
    }
    /// Changes the data-block size.
    #[must_use]
    pub const fn with_data_block_size(mut self, value: BlockSize) -> Self {
        self.data_block_size = value;
        self
    }
    /// Changes the hash-block size.
    #[must_use]
    pub const fn with_hash_block_size(mut self, value: BlockSize) -> Self {
        self.hash_block_size = value;
        self
    }
    /// Changes the protected block count.
    #[must_use]
    pub const fn with_data_blocks(mut self, value: NonZeroU64) -> Self {
        self.data_blocks = value;
        self
    }
}
