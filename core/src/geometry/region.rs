// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

#[cfg(feature = "tokio")]
use std::pin::Pin;
#[cfg(feature = "tokio")]
use std::task::{Context, Poll};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, AsyncWrite, ReadBuf};

use crate::traits::std::SyncData;

/// A zero-based device view over a contiguous block range.
///
/// Values of this type are returned by `Slice::slice` in [`crate::traits`].
/// Reads and writes stop at the selected extent.
#[derive(Debug)]
pub struct Region<T> {
    inner: T,
    start: u64,
    length: u64,
    count: u64,
    block_size: NonZeroU32,
    position: u64,
    #[cfg(feature = "tokio")]
    pending_seek: Option<u64>,
}

impl<T> Region<T> {
    pub(crate) fn byte_range(
        start: std::ops::Bound<u64>,
        end: std::ops::Bound<u64>,
        count: u64,
        block_size: NonZeroU32,
    ) -> io::Result<(u64, u64)> {
        use std::ops::Bound;
        let size = u64::from(block_size.get());
        let bytes = count.checked_mul(size).ok_or(io::ErrorKind::InvalidData)?;
        let start = match start {
            Bound::Included(start) => start,
            Bound::Excluded(start) => start.checked_add(1).ok_or(io::ErrorKind::InvalidInput)?,
            Bound::Unbounded => 0,
        };
        let end = match end {
            Bound::Excluded(end) => end,
            Bound::Included(end) => end.checked_add(1).ok_or(io::ErrorKind::InvalidInput)?,
            Bound::Unbounded => bytes,
        };
        if start > end || end > bytes || start % size != 0 || end % size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "byte range is outside the device or not block aligned",
            ));
        }
        Ok((start / size, (end - start) / size))
    }

    fn layout(
        start: u64,
        count: u64,
        device_count: u64,
        block_size: NonZeroU32,
    ) -> io::Result<(u64, u64)> {
        if start > device_count || count > device_count - start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device slice exceeds its block count",
            ));
        }
        let block_size = u64::from(block_size.get());
        let start = start.checked_mul(block_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "device slice offset overflows")
        })?;
        let length = count.checked_mul(block_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "device slice length overflows")
        })?;
        Ok((start, length))
    }

    pub(crate) fn from_sync(
        mut inner: T,
        start: u64,
        count: u64,
        device_count: u64,
        block_size: NonZeroU32,
    ) -> io::Result<Self>
    where
        T: Seek,
    {
        let (start, length) = Self::layout(start, count, device_count, block_size)?;
        inner.seek(SeekFrom::Start(start))?;
        Ok(Self {
            inner,
            start,
            length,
            count,
            block_size,
            position: 0,
            #[cfg(feature = "tokio")]
            pending_seek: None,
        })
    }

    #[cfg(feature = "tokio")]
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

    pub(crate) const fn reported_count(&self) -> u64 {
        self.count
    }

    pub(crate) const fn reported_block_size(&self) -> NonZeroU32 {
        self.block_size
    }

    fn seek_position(&self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
        };
        u64::try_from(position).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before the start of a device slice",
            )
        })
    }

    /// Removes the adapter and returns the underlying device.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsRef<T> for Region<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Region<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Read> Read for Region<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let limit = usize::try_from(remaining.min(output.len() as u64))
            .map_err(|_| io::Error::other("device slice read length exceeds usize"))?;
        if limit == 0 {
            return Ok(0);
        }
        let count = self.inner.read(&mut output[..limit])?;
        self.position = self.position.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "device slice position overflows",
            )
        })?;
        Ok(count)
    }
}

impl<T: Write> Write for Region<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let limit = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| io::Error::other("device slice write length exceeds usize"))?;
        if limit == 0 {
            return Ok(0);
        }
        let count = self.inner.write(&input[..limit])?;
        self.position = self.position.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "device slice position overflows",
            )
        })?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Seek> Seek for Region<T> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = self.seek_position(seek)?;
        let underlying = self.start.checked_add(position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "device slice seek overflows")
        })?;
        self.inner.seek(SeekFrom::Start(underlying))?;
        self.position = position;
        Ok(position)
    }
}

impl<T: SyncData> SyncData for Region<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

#[cfg(feature = "tokio")]
impl<T: crate::traits::tokio::SyncData> crate::traits::tokio::SyncData for Region<T> {
    fn sync_data(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        self.inner.sync_data()
    }
}

#[cfg(feature = "tokio")]
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

#[cfg(feature = "tokio")]
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

#[cfg(feature = "tokio")]
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
