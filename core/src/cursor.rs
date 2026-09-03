// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

#[cfg(feature = "futures-io")]
use futures_io::{AsyncRead, AsyncSeek, AsyncWrite};

use crate::{BlockCount, BlockSize, DynReadBlocks, DynWriteBlocks};
#[cfg(feature = "futures-io")]
use crate::{DynAsyncReadBlocks, DynAsyncWriteBlocks};

/// Adapts a bounded block device to byte-oriented I/O.
pub struct ByteCursor<D> {
    inner: D,
    position: u64,
    block: Box<[u8]>,
    #[cfg(feature = "futures-io")]
    operation: Operation,
}

#[cfg(feature = "futures-io")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Idle,
    Reading {
        index: u64,
        offset: usize,
        amount: usize,
    },
    ReadForWrite {
        index: u64,
        offset: usize,
        amount: usize,
    },
    Writing {
        index: u64,
        amount: usize,
    },
    Flushing,
}

impl<D: fmt::Debug> fmt::Debug for ByteCursor<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteCursor")
            .field("inner", &self.inner)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl<D: BlockCount + BlockSize> ByteCursor<D> {
    /// Construct a byte cursor at position zero.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the device's current byte
    /// length does not fit in `u64`.
    pub fn new(inner: D) -> io::Result<Self> {
        let block_size = inner.block_size();
        let block_size_u64 = u64::try_from(block_size.get())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block size exceeds u64"))?;
        if inner.block_count().checked_mul(block_size_u64).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block device byte length exceeds u64",
            ));
        }
        let block = vec![0; block_size.get()].into_boxed_slice();
        Ok(Self {
            inner,
            position: 0,
            block,
            #[cfg(feature = "futures-io")]
            operation: Operation::Idle,
        })
    }

    fn byte_len(&self) -> io::Result<u64> {
        let block_size = u64::try_from(self.block.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block size exceeds u64"))?;
        self.inner
            .block_count()
            .checked_mul(block_size)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block device byte length exceeds u64",
                )
            })
    }

    fn seek_to(&mut self, position: SeekFrom) -> io::Result<u64> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous byte operation is in progress",
            ));
        }
        let next = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => i128::from(self.byte_len()?) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek position is outside the address space",
            )
        })?;
        Ok(self.position)
    }
}

impl<D: BlockCount + DynReadBlocks> Read for ByteCursor<D> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous byte operation is in progress",
            ));
        }
        if output.is_empty() || self.position >= self.byte_len()? {
            return Ok(0);
        }

        let mut copied = 0;
        while copied < output.len() && self.position < self.byte_len()? {
            let block_size = self.block.len();
            let block_size_u64 = u64::try_from(block_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "block size exceeds u64")
            })?;
            let index = self.position / block_size_u64;
            let offset = usize::try_from(self.position % block_size_u64).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "block offset exceeds usize")
            })?;
            let remaining = usize::try_from(self.byte_len()? - self.position).unwrap_or(usize::MAX);
            let amount = (block_size - offset)
                .min(output.len() - copied)
                .min(remaining);
            if let Err(error) = self.inner.read_block(index, &mut self.block) {
                return if copied == 0 { Err(error) } else { Ok(copied) };
            }
            output[copied..copied + amount].copy_from_slice(&self.block[offset..offset + amount]);
            copied += amount;
            self.position += amount as u64;
        }
        Ok(copied)
    }
}

impl<D: BlockCount + DynReadBlocks + DynWriteBlocks> Write for ByteCursor<D> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous byte operation is in progress",
            ));
        }
        if input.is_empty() {
            return Ok(0);
        }
        let byte_len = self.byte_len()?;
        if self.position >= byte_len {
            return Ok(0);
        }

        let mut copied = 0;
        while copied < input.len() && self.position < byte_len {
            let block_size = self.block.len();
            let block_size_u64 = u64::try_from(block_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "block size exceeds u64")
            })?;
            let index = self.position / block_size_u64;
            let offset = usize::try_from(self.position % block_size_u64).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "block offset exceeds usize")
            })?;
            let remaining = usize::try_from(byte_len - self.position).unwrap_or(usize::MAX);
            let amount = (block_size - offset)
                .min(input.len() - copied)
                .min(remaining);

            let result = if offset == 0 && amount == block_size {
                self.inner
                    .write_block(index, &input[copied..copied + amount])
            } else {
                self.inner
                    .read_block(index, &mut self.block)
                    .and_then(|()| {
                        self.block[offset..offset + amount]
                            .copy_from_slice(&input[copied..copied + amount]);
                        self.inner.write_block(index, &self.block)
                    })
            };
            if let Err(error) = result {
                return if copied == 0 { Err(error) } else { Ok(copied) };
            }
            copied += amount;
            self.position += amount as u64;
        }
        Ok(copied)
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(feature = "futures-io")]
        if self.operation != Operation::Idle {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous byte operation is in progress",
            ));
        }
        self.inner.flush()
    }
}

impl<D: BlockCount + BlockSize> Seek for ByteCursor<D> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.seek_to(position)
    }
}

#[cfg(feature = "futures-io")]
impl<D: BlockCount + DynAsyncReadBlocks + Unpin> AsyncRead for ByteCursor<D> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if output.is_empty() && this.operation == Operation::Idle {
            return Poll::Ready(Ok(0));
        }
        if this.operation == Operation::Idle {
            let byte_len = match this.byte_len() {
                Ok(byte_len) => byte_len,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if this.position >= byte_len {
                return Poll::Ready(Ok(0));
            }
            let block_size = this.block.len();
            let Ok(block_size_u64) = u64::try_from(block_size) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block size exceeds u64",
                )));
            };
            let index = this.position / block_size_u64;
            let Ok(offset) = usize::try_from(this.position % block_size_u64) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block offset exceeds usize",
                )));
            };
            let remaining = usize::try_from(byte_len - this.position).unwrap_or(usize::MAX);
            let amount = (block_size - offset).min(output.len()).min(remaining);
            this.operation = Operation::Reading {
                index,
                offset,
                amount,
            };
        }

        let Operation::Reading {
            index,
            offset,
            amount,
        } = this.operation
        else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another asynchronous byte operation is in progress",
            )));
        };
        match Pin::new(&mut this.inner).poll_read_block(cx, index, &mut this.block) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.operation = Operation::Idle;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                if output.len() < amount {
                    this.operation = Operation::Idle;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "read buffer changed while the operation was pending",
                    )));
                }
                output[..amount].copy_from_slice(&this.block[offset..offset + amount]);
                this.position += amount as u64;
                this.operation = Operation::Idle;
                Poll::Ready(Ok(amount))
            }
        }
    }
}

#[cfg(feature = "futures-io")]
impl<D: BlockCount + DynAsyncReadBlocks + DynAsyncWriteBlocks + Unpin> AsyncWrite
    for ByteCursor<D>
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() && this.operation == Operation::Idle {
            return Poll::Ready(Ok(0));
        }
        if this.operation == Operation::Idle {
            let byte_len = match this.byte_len() {
                Ok(byte_len) => byte_len,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if this.position >= byte_len {
                return Poll::Ready(Ok(0));
            }
            let block_size = this.block.len();
            let Ok(block_size_u64) = u64::try_from(block_size) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block size exceeds u64",
                )));
            };
            let index = this.position / block_size_u64;
            let Ok(offset) = usize::try_from(this.position % block_size_u64) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "block offset exceeds usize",
                )));
            };
            let remaining = usize::try_from(byte_len - this.position).unwrap_or(usize::MAX);
            let amount = (block_size - offset).min(input.len()).min(remaining);
            if offset == 0 && amount == block_size {
                this.block.copy_from_slice(&input[..amount]);
                this.operation = Operation::Writing { index, amount };
            } else {
                this.operation = Operation::ReadForWrite {
                    index,
                    offset,
                    amount,
                };
            }
        }

        loop {
            match this.operation {
                Operation::ReadForWrite {
                    index,
                    offset,
                    amount,
                } => match Pin::new(&mut this.inner).poll_read_block(cx, index, &mut this.block) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.operation = Operation::Idle;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        if input.len() < amount {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "write buffer changed while the operation was pending",
                            )));
                        }
                        this.block[offset..offset + amount].copy_from_slice(&input[..amount]);
                        this.operation = Operation::Writing { index, amount };
                    }
                },
                Operation::Writing { index, amount } => {
                    if input.len() < amount {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "write buffer changed while the operation was pending",
                        )));
                    }
                    match Pin::new(&mut this.inner).poll_write_block(cx, index, &this.block) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            this.operation = Operation::Idle;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(())) => {
                            this.position += amount as u64;
                            this.operation = Operation::Idle;
                            return Poll::Ready(Ok(amount));
                        }
                    }
                }
                _ => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "another asynchronous byte operation is in progress",
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
                "another asynchronous byte operation is in progress",
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

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(feature = "futures-io")]
impl<D: BlockCount + BlockSize + Unpin> AsyncSeek for ByteCursor<D> {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Poll::Ready(self.get_mut().seek_to(position))
    }
}
