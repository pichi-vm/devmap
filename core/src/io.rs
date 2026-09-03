// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

#[cfg(feature = "futures-io")]
use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};

#[cfg(feature = "futures-io")]
use crate::{AsyncReadBlocks, AsyncWriteBlocks, DynAsyncReadBlocks, DynAsyncWriteBlocks};
use crate::{BlockCount, BlockSize, DynReadBlocks, DynWriteBlocks, ReadBlocks, WriteBlocks};

/// Adapts bounded, seekable byte storage to block I/O.
///
/// A zero block size is rejected at compile time:
///
/// ```compile_fail
/// use devmap_core::BlockIo;
/// use std::io::Cursor;
///
/// let _ = BlockIo::<_, 0>::new(Cursor::new(Vec::<u8>::new()), 1);
/// ```
#[derive(Debug)]
pub struct BlockIo<T, const SIZE: usize> {
    inner: T,
    block_count: u64,
    #[cfg(feature = "futures-io")]
    operation: Operation,
}

#[cfg(feature = "futures-io")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Idle,
    ReadSeek { index: u64 },
    Reading { index: u64, read: usize },
    WriteSeek { index: u64 },
    Writing { index: u64, written: usize },
    Flushing,
}

impl<T, const SIZE: usize> BlockIo<T, SIZE> {
    const BLOCK_SIZE: NonZeroUsize = match NonZeroUsize::new(SIZE) {
        Some(size) => size,
        None => panic!("block size must be nonzero"),
    };

    /// Construct a block view containing `block_count` blocks.
    ///
    /// The constructor does not inspect `inner`. A short underlying input is
    /// reported when its missing block is read.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the byte length does not fit
    /// in `u64`.
    pub fn new(inner: T, block_count: u64) -> io::Result<Self> {
        let block_size = Self::BLOCK_SIZE.get() as u64;
        if block_count.checked_mul(block_size).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block device byte length exceeds u64",
            ));
        }
        Ok(Self {
            inner,
            block_count,
            #[cfg(feature = "futures-io")]
            operation: Operation::Idle,
        })
    }

    fn offset(index: u64) -> io::Result<u64> {
        index
            .checked_mul(SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "block offset exceeds u64"))
    }
}

impl<T, const SIZE: usize> BlockSize for BlockIo<T, SIZE> {
    fn block_size(&self) -> NonZeroUsize {
        Self::BLOCK_SIZE
    }
}

impl<T, const SIZE: usize> BlockCount for BlockIo<T, SIZE> {
    fn block_count(&self) -> u64 {
        self.block_count
    }
}

impl<T: Read + Seek, const SIZE: usize> ReadBlocks<SIZE> for BlockIo<T, SIZE> {
    fn read_block(&mut self, index: u64, block: &mut [u8; SIZE]) -> io::Result<()> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous block operation is in progress",
            ));
        }
        if index >= self.block_count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "block index is outside the device",
            ));
        }
        self.inner.seek(SeekFrom::Start(Self::offset(index)?))?;
        self.inner.read_exact(block)
    }
}

impl<T: Read + Seek, const SIZE: usize> DynReadBlocks for BlockIo<T, SIZE> {
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

impl<T: Write + Seek, const SIZE: usize> WriteBlocks<SIZE> for BlockIo<T, SIZE> {
    fn write_block(&mut self, index: u64, block: &[u8; SIZE]) -> io::Result<()> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous block operation is in progress",
            ));
        }
        if index >= self.block_count {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "block index is outside the device",
            ));
        }
        self.inner.seek(SeekFrom::Start(Self::offset(index)?))?;
        self.inner.write_all(block)
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous block operation is in progress",
            ));
        }
        self.inner.flush()
    }
}

impl<T: Write + Seek, const SIZE: usize> DynWriteBlocks for BlockIo<T, SIZE> {
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
impl<T: AsyncRead + AsyncSeek + Unpin, const SIZE: usize> AsyncReadBlocks<SIZE>
    for BlockIo<T, SIZE>
{
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8; SIZE],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if index >= this.block_count {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "block index is outside the device",
            )));
        }
        if this.operation == Operation::Idle {
            this.operation = Operation::ReadSeek { index };
        }

        loop {
            match this.operation {
                Operation::ReadSeek { index: active } if active == index => {
                    match Pin::new(&mut this.inner).poll_seek(
                        cx,
                        SeekFrom::Start(match Self::offset(index) {
                            Ok(offset) => offset,
                            Err(error) => {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(error));
                            }
                        }),
                    ) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(_)) => {
                            this.operation = Operation::Reading { index, read: 0 };
                        }
                    }
                }
                Operation::Reading {
                    index: active,
                    read,
                } if active == index => {
                    match Pin::new(&mut this.inner).poll_read(cx, &mut block[read..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(0)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        Poll::Ready(Ok(count)) => {
                            let Some(read) = read.checked_add(count) else {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(io::Error::other(
                                    "asynchronous read count overflows",
                                )));
                            };
                            if read > SIZE {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(io::Error::other(
                                    "asynchronous input read more bytes than requested",
                                )));
                            }
                            if read == SIZE {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Ok(()));
                            }
                            this.operation = Operation::Reading { index, read };
                        }
                    }
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "another asynchronous block operation is in progress",
                    )));
                }
            }
        }
    }
}

#[cfg(feature = "futures-io")]
impl<T: AsyncRead + AsyncSeek + Unpin, const SIZE: usize> DynAsyncReadBlocks for BlockIo<T, SIZE> {
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
impl<T: AsyncWrite + AsyncSeek + Unpin, const SIZE: usize> AsyncWriteBlocks<SIZE>
    for BlockIo<T, SIZE>
{
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8; SIZE],
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if index >= this.block_count {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "block index is outside the device",
            )));
        }
        if this.operation == Operation::Idle {
            this.operation = Operation::WriteSeek { index };
        }

        loop {
            match this.operation {
                Operation::WriteSeek { index: active } if active == index => {
                    match Pin::new(&mut this.inner).poll_seek(
                        cx,
                        SeekFrom::Start(match Self::offset(index) {
                            Ok(offset) => offset,
                            Err(error) => {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(error));
                            }
                        }),
                    ) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(_)) => {
                            this.operation = Operation::Writing { index, written: 0 };
                        }
                    }
                }
                Operation::Writing {
                    index: active,
                    written,
                } if active == index => {
                    match Pin::new(&mut this.inner).poll_write(cx, &block[written..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(0)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        Poll::Ready(Ok(count)) => {
                            let Some(written) = written.checked_add(count) else {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(io::Error::other(
                                    "asynchronous write count overflows",
                                )));
                            };
                            if written > SIZE {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Err(io::Error::other(
                                    "asynchronous output wrote more bytes than requested",
                                )));
                            }
                            if written == SIZE {
                                this.operation = Operation::Idle;
                                return Poll::Ready(Ok(()));
                            }
                            this.operation = Operation::Writing { index, written };
                        }
                    }
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "another asynchronous block operation is in progress",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.operation == Operation::Idle {
            this.operation = Operation::Flushing;
        }
        if this.operation != Operation::Flushing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another asynchronous block operation is in progress",
            )));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.operation = Operation::Idle;
                Poll::Ready(result)
            }
        }
    }
}

#[cfg(feature = "futures-io")]
impl<T: AsyncWrite + AsyncSeek + Unpin, const SIZE: usize> DynAsyncWriteBlocks
    for BlockIo<T, SIZE>
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
        <Self as AsyncWriteBlocks<SIZE>>::poll_write_block(self, cx, index, block)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWriteBlocks<SIZE>>::poll_flush(self, cx)
    }
}
