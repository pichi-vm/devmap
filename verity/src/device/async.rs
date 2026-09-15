// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use devmap_core::traits::tokio::Geometry;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use super::Verity;
use crate::{Hashes, traits::tokio::Open};

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Idle,
    Start { block: u64 },
    Seeking { block: u64 },
    Reading { block: u64, filled: usize },
    Authenticating { block: u64 },
}

impl<D: Geometry + Send, H: Geometry + Send> Open<D, Hashes<H>> for Verity<D, H> {
    async fn open(mut data: D, mut hashes: Hashes<H>, root: &[u8]) -> io::Result<Self> {
        hashes.validate_storage_async().await?;
        let block_size = data.block_size()?;
        let count = data.count().await?;
        Self::new(data, hashes, root, block_size, count)
    }
}

impl<D: AsyncRead + AsyncSeek + Unpin, H: AsyncRead + AsyncSeek + Unpin> Verity<D, H> {
    fn poll_block(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                Phase::Idle => {
                    let block =
                        self.position / u64::from(self.parameters().data_block_size().get());
                    if self.cached == Some(block) {
                        return Poll::Ready(Ok(()));
                    }
                    self.prepare_buffer();
                    self.phase = Phase::Start { block };
                }
                Phase::Start { block } => {
                    ready!(Pin::new(&mut self.data).poll_complete(cx))?;
                    let offset = block * u64::from(self.parameters().data_block_size().get());
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
                    self.phase = if filled == self.buffer.len() {
                        Phase::Authenticating { block }
                    } else {
                        Phase::Reading { block, filled }
                    };
                }
                Phase::Authenticating { block } => {
                    ready!(
                        self.hashes
                            .poll_authenticate(cx, block, &self.buffer, &self.root)
                    )?;
                    self.cached = Some(block);
                    return Poll::Ready(Ok(()));
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
        if output.remaining() == 0 || this.position >= (this.parameters().layout.data_size as u64) {
            return Poll::Ready(Ok(()));
        }
        let result = this.poll_block(cx);
        if result.is_ready() {
            this.phase = Phase::Idle;
        }
        ready!(result)?;
        let within =
            (this.position % u64::from(this.parameters().data_block_size().get())) as usize;
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
        Box::pin(std::future::ready(Ok((self.parameters().layout.data_size
            as u64)
            / u64::from(self.block_size.get()))))
    }
}
