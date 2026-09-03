// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

/// Reports the block size used by a runtime-sized block device.
///
/// The reported size must not change during the lifetime of the device.
pub trait BlockSize {
    /// Return the number of bytes in each block.
    fn block_size(&self) -> NonZeroUsize;
}

impl<T: BlockSize + ?Sized> BlockSize for &mut T {
    fn block_size(&self) -> NonZeroUsize {
        (**self).block_size()
    }
}
