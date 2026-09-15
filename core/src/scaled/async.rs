// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io::{self, IoSlice, SeekFrom};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

use super::Scaled;
use crate::traits::tokio::{Geometry, SyncData};

impl<T: SyncData> SyncData for Scaled<T> {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        self.inner.sync_data()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Scaled<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

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

impl<T: AsyncSeek + Unpin> AsyncSeek for Scaled<T> {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.get_mut().inner).start_seek(position)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.get_mut().inner).poll_complete(cx)
    }
}

impl<T: Geometry> Geometry for Scaled<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        let multiplier = u64::from(self.multiplier.get());
        let count = self.inner.count();
        Box::pin(async move {
            let count = count.await?;
            if count % multiplier != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "underlying block count is incompatible with the scaled block size",
                ));
            }
            Ok(count / multiplier)
        })
    }
}
