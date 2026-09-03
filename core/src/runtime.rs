// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroUsize;

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

#[cfg(feature = "futures-io")]
use crate::{AsyncReadBlocks, AsyncWriteBlocks, DynAsyncReadBlocks, DynAsyncWriteBlocks};
use crate::{BlockCount, BlockSize, DynReadBlocks, DynWriteBlocks, ReadBlocks, WriteBlocks};

/// Adapts const-sized block I/O to runtime-sized block I/O.
#[derive(Debug)]
pub struct Runtime<D, const SIZE: usize> {
    inner: D,
}

impl<D, const SIZE: usize> Runtime<D, SIZE> {
    const BLOCK_SIZE: NonZeroUsize = match NonZeroUsize::new(SIZE) {
        Some(size) => size,
        None => panic!("block size must be nonzero"),
    };

    /// Wrap a const-sized block device.
    pub const fn new(inner: D) -> Self {
        let _ = Self::BLOCK_SIZE;
        Self { inner }
    }
}

impl<D, const SIZE: usize> BlockSize for Runtime<D, SIZE> {
    fn block_size(&self) -> NonZeroUsize {
        Self::BLOCK_SIZE
    }
}

impl<D: BlockCount, const SIZE: usize> BlockCount for Runtime<D, SIZE> {
    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }
}

impl<D: ReadBlocks<SIZE>, const SIZE: usize> DynReadBlocks for Runtime<D, SIZE> {
    fn read_block(&mut self, index: u64, block: &mut [u8]) -> io::Result<()> {
        let block = <&mut [u8; SIZE]>::try_from(block).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )
        })?;
        self.inner.read_block(index, block)
    }
}

impl<D: WriteBlocks<SIZE>, const SIZE: usize> DynWriteBlocks for Runtime<D, SIZE> {
    fn write_block(&mut self, index: u64, block: &[u8]) -> io::Result<()> {
        let block = <&[u8; SIZE]>::try_from(block).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )
        })?;
        self.inner.write_block(index, block)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncReadBlocks<SIZE> + Unpin, const SIZE: usize> DynAsyncReadBlocks for Runtime<D, SIZE> {
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8],
    ) -> Poll<io::Result<()>> {
        let Ok(block) = <&mut [u8; SIZE]>::try_from(block) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )));
        };
        Pin::new(&mut self.get_mut().inner).poll_read_block(cx, index, block)
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncWriteBlocks<SIZE> + Unpin, const SIZE: usize> DynAsyncWriteBlocks
    for Runtime<D, SIZE>
{
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8],
    ) -> Poll<io::Result<()>> {
        let Ok(block) = <&[u8; SIZE]>::try_from(block) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )));
        };
        Pin::new(&mut self.get_mut().inner).poll_write_block(cx, index, block)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
}
