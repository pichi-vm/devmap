// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

#[cfg(feature = "futures-io")]
use crate::{AsyncReadBlocks, AsyncWriteBlocks};
use crate::{ReadBlocks, WriteBlocks};

/// An unbounded zero-filled block device that discards writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Zero;

impl<const SIZE: usize> ReadBlocks<SIZE> for Zero {
    fn read_block(&mut self, index: u64, block: &mut [u8; SIZE]) -> std::io::Result<()> {
        const { assert!(SIZE != 0, "block size must be nonzero") }
        let _ = index;
        block.fill(0);
        Ok(())
    }
}

impl<const SIZE: usize> WriteBlocks<SIZE> for Zero {
    fn write_block(&mut self, index: u64, _block: &[u8; SIZE]) -> std::io::Result<()> {
        const { assert!(SIZE != 0, "block size must be nonzero") }
        let _ = index;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        const { assert!(SIZE != 0, "block size must be nonzero") }
        Ok(())
    }
}

#[cfg(feature = "futures-io")]
impl<const SIZE: usize> AsyncReadBlocks<SIZE> for Zero {
    fn poll_read_block(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8; SIZE],
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().read_block(index, block))
    }
}

#[cfg(feature = "futures-io")]
impl<const SIZE: usize> AsyncWriteBlocks<SIZE> for Zero {
    fn poll_write_block(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        index: u64,
        block: &[u8; SIZE],
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().write_block(index, block))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(<Self as WriteBlocks<SIZE>>::flush(self.get_mut()))
    }
}
