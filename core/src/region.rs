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

/// A bounded region of another block device.
#[derive(Debug)]
pub struct Region<D, const SIZE: usize> {
    inner: D,
    start: u64,
    block_count: u64,
}

impl<D, const SIZE: usize> Region<D, SIZE> {
    const BLOCK_SIZE: NonZeroUsize = match NonZeroUsize::new(SIZE) {
        Some(size) => size,
        None => panic!("block size must be nonzero"),
    };

    /// Construct a region beginning at `start` in `inner`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the end block is not
    /// representable by `u64`.
    pub fn new(inner: D, start: u64, block_count: u64) -> io::Result<Self> {
        let _ = Self::BLOCK_SIZE;
        if start.checked_add(block_count).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block region exceeds the address space",
            ));
        }
        Ok(Self {
            inner,
            start,
            block_count,
        })
    }
}

impl<D, const SIZE: usize> BlockSize for Region<D, SIZE> {
    fn block_size(&self) -> NonZeroUsize {
        Self::BLOCK_SIZE
    }
}

impl<D, const SIZE: usize> BlockCount for Region<D, SIZE> {
    fn block_count(&self) -> u64 {
        self.block_count
    }
}

impl<D: ReadBlocks<SIZE>, const SIZE: usize> ReadBlocks<SIZE> for Region<D, SIZE> {
    fn read_block(&mut self, index: u64, block: &mut [u8; SIZE]) -> io::Result<()> {
        if index < self.block_count {
            return self.inner.read_block(self.start + index, block);
        }
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "block index is outside the region",
        ))
    }
}

impl<D: ReadBlocks<SIZE>, const SIZE: usize> DynReadBlocks for Region<D, SIZE> {
    fn read_block(&mut self, index: u64, block: &mut [u8]) -> io::Result<()> {
        let block = <&mut [u8; SIZE]>::try_from(block).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )
        })?;
        <Self as ReadBlocks<SIZE>>::read_block(self, index, block)
    }
}

impl<D: WriteBlocks<SIZE>, const SIZE: usize> WriteBlocks<SIZE> for Region<D, SIZE> {
    fn write_block(&mut self, index: u64, block: &[u8; SIZE]) -> io::Result<()> {
        if index < self.block_count {
            return self.inner.write_block(self.start + index, block);
        }
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "block index is outside the region",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<D: WriteBlocks<SIZE>, const SIZE: usize> DynWriteBlocks for Region<D, SIZE> {
    fn write_block(&mut self, index: u64, block: &[u8]) -> io::Result<()> {
        let block = <&[u8; SIZE]>::try_from(block).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer length does not match the block size",
            )
        })?;
        <Self as WriteBlocks<SIZE>>::write_block(self, index, block)
    }

    fn flush(&mut self) -> io::Result<()> {
        <Self as WriteBlocks<SIZE>>::flush(self)
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncReadBlocks<SIZE> + Unpin, const SIZE: usize> AsyncReadBlocks<SIZE>
    for Region<D, SIZE>
{
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8; SIZE],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if index < this.block_count {
            return Pin::new(&mut this.inner).poll_read_block(cx, this.start + index, block);
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "block index is outside the region",
        )))
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncReadBlocks<SIZE> + Unpin, const SIZE: usize> DynAsyncReadBlocks for Region<D, SIZE> {
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
        <Self as AsyncReadBlocks<SIZE>>::poll_read_block(self, cx, index, block)
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncWriteBlocks<SIZE> + Unpin, const SIZE: usize> AsyncWriteBlocks<SIZE>
    for Region<D, SIZE>
{
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8; SIZE],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if index < this.block_count {
            return Pin::new(&mut this.inner).poll_write_block(cx, this.start + index, block);
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "block index is outside the region",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
}

#[cfg(feature = "futures-io")]
impl<D: AsyncWriteBlocks<SIZE> + Unpin, const SIZE: usize> DynAsyncWriteBlocks for Region<D, SIZE> {
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
        <Self as AsyncWriteBlocks<SIZE>>::poll_write_block(self, cx, index, block)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWriteBlocks<SIZE>>::poll_flush(self, cx)
    }
}
