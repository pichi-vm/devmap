// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, ready};
use std::io::{self, SeekFrom};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, AsyncWrite, ReadBuf};

use super::Region;
use crate::traits::tokio::{Geometry, SyncData};

impl<T> Region<T> {
    pub(crate) async fn from_async(
        mut inner: T,
        start: u64,
        count: u64,
        device_count: u64,
        block_size: NonZeroU32,
    ) -> io::Result<Self>
    where
        T: AsyncSeek + Unpin,
    {
        let (start, length) = Self::layout(start, count, device_count, block_size)?;
        inner.seek(SeekFrom::Start(start)).await?;
        Ok(Self {
            inner,
            start,
            length,
            count,
            block_size,
            position: 0,
            pending_seek: None,
        })
    }
}

impl<T: SyncData> SyncData for Region<T> {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        self.inner.sync_data()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Region<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = this.length.saturating_sub(this.position);
        let limit = usize::try_from(remaining.min(output.remaining() as u64))
            .map_err(|_| io::Error::other("device slice read length exceeds usize"))?;
        if limit == 0 {
            return Poll::Ready(Ok(()));
        }
        let available = output.initialize_unfilled_to(limit);
        let mut limited = ReadBuf::new(available);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let count = limited.filled().len();
                output.advance(count);
                this.position += count as u64;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Region<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let remaining = this.length.saturating_sub(this.position);
        let limit = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| io::Error::other("device slice write length exceeds usize"))?;
        if limit == 0 {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut this.inner).poll_write(cx, &input[..limit]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(count)) => {
                this.position += count as u64;
                Poll::Ready(Ok(count))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<T: AsyncSeek + Unpin> AsyncSeek for Region<T> {
    fn start_seek(self: Pin<&mut Self>, seek: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.pending_seek.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another device slice seek is in progress",
            ));
        }
        let position = this.seek_position(seek)?;
        let underlying = this.start.checked_add(position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "device slice seek overflows")
        })?;
        Pin::new(&mut this.inner).start_seek(SeekFrom::Start(underlying))?;
        this.pending_seek = Some(position);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_complete(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.pending_seek = None;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(underlying)) => {
                let position = underlying.checked_sub(this.start).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "underlying device sought before the slice",
                    )
                })?;
                this.position = position;
                this.pending_seek = None;
                Poll::Ready(Ok(position))
            }
        }
    }
}

impl<T> Geometry for Region<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(ready(Ok(self.count)))
    }
}
