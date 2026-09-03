// SPDX-License-Identifier: Apache-2.0

/// Reports the configured number of addressable blocks in a device.
///
/// Block I/O does not require this capability. Consumers that need a bounded
/// device, such as byte cursors and network block-device exports, can require
/// it separately.
pub trait BlockCount {
    /// Return the configured number of addressable blocks.
    fn block_count(&self) -> u64;
}

impl<T: BlockCount + ?Sized> BlockCount for &mut T {
    fn block_count(&self) -> u64 {
        (**self).block_count()
    }
}
