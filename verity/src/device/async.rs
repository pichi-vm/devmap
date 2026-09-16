// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use devmap_core::traits::tokio::Geometry;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use super::Verity;
use crate::{Hashes, Options, traits::tokio::Open};

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Idle,
    Start { block: u64 },
    Seeking { block: u64 },
    Reading { block: u64, filled: usize },
    Lookup { block: u64 },
}

impl<D: Geometry + Send, H: Geometry + Send> Open<D, H> for Options<'_> {
    async fn open(
        self,
        mut data: D,
        mut hashes: Hashes<H>,
        root: &[u8],
    ) -> io::Result<Verity<D, H>> {
        hashes.validate_storage_async().await?;
        let block_size = data.block_size()?;
        let count = data.count().await?;
        Verity::new(data, hashes, root, self, block_size, count)
    }
}

impl<D: AsyncRead + AsyncSeek + Unpin, H: AsyncRead + AsyncSeek + Unpin> Verity<D, H> {
    fn poll_block(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                Phase::Idle => {
                    let block = self.position / self.data_block_size();
                    if self.cached == Some(block) {
                        return Poll::Ready(Ok(()));
                    }
                    self.prepare_buffer()?;
                    self.phase = if self.was_verified(block) {
                        Phase::Start { block }
                    } else {
                        Phase::Lookup { block }
                    };
                }
                Phase::Lookup { block } => {
                    match ready!(self.hashes.poll_lookup(cx, block, &self.root)) {
                        Ok(expected) => {
                            let d = self
                                .digests
                                .as_mut()
                                .ok_or_else(|| io::Error::other("missing data verifier"))?;
                            d.expected.copy_from_slice(expected);
                            self.compare = true;
                        }
                        Err(error)
                            if Self::ignore_mismatch(self.options.corruption_policy, &error) => {}
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                    if self.zero_block(block) {
                        self.phase = Phase::Idle;
                        return Poll::Ready(Ok(()));
                    }
                    self.phase = Phase::Start { block };
                }
                Phase::Start { block } => {
                    ready!(Pin::new(&mut self.data).poll_complete(cx))?;
                    let offset = block * self.data_block_size();
                    Pin::new(&mut self.data).start_seek(io::SeekFrom::Start(offset))?;
                    self.phase = Phase::Seeking { block };
                }
                Phase::Seeking { block } => {
                    ready!(Pin::new(&mut self.data).poll_complete(cx))?;
                    self.phase = Phase::Reading { block, filled: 0 };
                }
                Phase::Reading { block, filled } => {
                    let mut output = ReadBuf::new(&mut self.buffer[filled..]);
                    match ready!(Pin::new(&mut self.data).poll_read(cx, &mut output)) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    }
                    let count = output.filled().len();
                    if count == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let filled = filled + count;
                    if filled == self.buffer.len() {
                        self.finish_block(block)?;
                        self.phase = Phase::Idle;
                        return Poll::Ready(Ok(()));
                    }
                    self.phase = Phase::Reading { block, filled };
                }
            }
        }
    }
}

impl<D: AsyncRead + AsyncSeek + Unpin, H: AsyncRead + AsyncSeek + Unpin> AsyncRead
    for Verity<D, H>
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.position >= this.data_size() {
            return Poll::Ready(Ok(()));
        }
        let result = this.poll_block(cx);
        if result.is_ready() {
            this.phase = Phase::Idle;
        }
        ready!(result)?;
        let within = (this.position % this.data_block_size()) as usize;
        let count = output.remaining().min(this.buffer.len() - within);
        output.put_slice(&this.buffer[within..within + count]);
        this.position += count as u64;
        Poll::Ready(Ok(()))
    }
}

impl<D: Unpin, H: Unpin> AsyncSeek for Verity<D, H> {
    fn start_seek(self: Pin<&mut Self>, seek: io::SeekFrom) -> io::Result<()> {
        self.get_mut().seek_position(seek).map(|_| ())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        Poll::Ready(this.ensure_idle().map(|()| this.position))
    }
}

impl<D, H> Geometry for Verity<D, H> {
    fn block_size(&self) -> io::Result<std::num::NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(
            self.data_size() / u64::from(self.block_size.get())
        )))
    }
}
