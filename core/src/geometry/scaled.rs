// SPDX-License-Identifier: Apache-2.0

use std::io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

#[cfg(feature = "tokio")]
use std::pin::Pin;
#[cfg(feature = "tokio")]
use std::task::{Context, Poll};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use crate::traits::std::SyncData;

/// A device presented using larger blocks.
///
/// Values of this type are returned by `Scale::scale` and `Scale::scale_to`
/// in [`crate::traits`].
/// The adapter forwards byte I/O unchanged.
#[derive(Debug)]
pub struct Scaled<T> {
    inner: T,
    multiplier: NonZeroU32,
    block_size: NonZeroU32,
}

impl<T> Scaled<T> {
    pub(crate) fn multiplier_for(
        current: NonZeroU32,
        requested: NonZeroU32,
    ) -> io::Result<NonZeroU32> {
        if requested.get() % current.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requested block size is not a multiple of the device block size",
            ));
        }
        NonZeroU32::new(requested.get() / current.get()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "requested block size is smaller than the device block size",
            )
        })
    }

    pub(crate) fn new(
        inner: T,
        multiplier: NonZeroU32,
        block_size: NonZeroU32,
        count: u64,
    ) -> io::Result<Self> {
        if !multiplier.get().is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block-size multiplier must be a power of two",
            ));
        }
        if count % u64::from(multiplier.get()) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block count is not divisible by the block-size multiplier",
            ));
        }
        u64::from(block_size.get())
            .checked_mul(count)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "device geometry overflows")
            })?;
        let block_size = block_size
            .get()
            .checked_mul(multiplier.get())
            .and_then(NonZeroU32::new)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "scaled block size exceeds u32")
            })?;
        Ok(Self {
            inner,
            multiplier,
            block_size,
        })
    }

    pub(crate) const fn multiplier(&self) -> NonZeroU32 {
        self.multiplier
    }

    pub(crate) const fn reported_block_size(&self) -> NonZeroU32 {
        self.block_size
    }

    /// Removes the adapter and returns the underlying device.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsRef<T> for Scaled<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Scaled<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Read> Read for Scaled<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }

    fn read_vectored(&mut self, output: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(output)
    }
}

impl<T: Write> Write for Scaled<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.inner.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write_vectored(&mut self, input: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(input)
    }
}

impl<T: Seek> Seek for Scaled<T> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

impl<T: SyncData> SyncData for Scaled<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

#[cfg(feature = "tokio")]
impl<T: crate::traits::tokio::SyncData> crate::traits::tokio::SyncData for Scaled<T> {
    fn sync_data(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        self.inner.sync_data()
    }
}

#[cfg(feature = "tokio")]
impl<T: AsyncRead + Unpin> AsyncRead for Scaled<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

#[cfg(feature = "tokio")]
impl<T: AsyncWrite + Unpin> AsyncWrite for Scaled<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, input)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(feature = "tokio")]
impl<T: AsyncSeek + Unpin> AsyncSeek for Scaled<T> {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.get_mut().inner).start_seek(position)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.get_mut().inner).poll_complete(cx)
    }
}
