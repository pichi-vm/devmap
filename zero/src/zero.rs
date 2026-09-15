// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroU32;

#[cfg(feature = "tokio")]
use std::pin::Pin;
#[cfg(feature = "tokio")]
use std::task::{Context, Poll};

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use devmap_core::traits::std::Geometry;

/// A fixed-length, seekable source of zero bytes.
///
/// Reads return zeroes until the configured length and then return EOF. Seeking
/// beyond the end is allowed; seeking before byte zero returns
/// [`io::ErrorKind::InvalidInput`]. The stream allocates no backing storage and
/// reports a block size of one byte.
///
/// With the `tokio` feature, the same type also implements Tokio's asynchronous
/// read and seek traits.
#[derive(Debug, Clone)]
pub struct Zero {
    length: u64,
    position: u64,
}

impl Zero {
    /// Creates a zero-filled stream with a length of `length` bytes.
    #[must_use]
    pub const fn new(length: u64) -> Self {
        Self {
            length,
            position: 0,
        }
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
                "cannot seek before the start of a zero stream",
            )
        })
    }
}

impl Read for Zero {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let count = usize::try_from(remaining.min(output.len() as u64))
            .map_err(|_| io::Error::other("zero stream read length exceeds usize"))?;
        output[..count].fill(0);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Zero {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        self.position = self.seek_position(seek)?;
        Ok(self.position)
    }
}

impl Geometry for Zero {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }

    fn count(&mut self) -> io::Result<u64> {
        Ok(self.length)
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl AsyncRead for Zero {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = self.length.saturating_sub(self.position);
        let count = usize::try_from(remaining.min(output.remaining() as u64))
            .map_err(|_| io::Error::other("zero stream read length exceeds usize"))?;
        output.initialize_unfilled_to(count).fill(0);
        output.advance(count);
        self.position += count as u64;
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl AsyncSeek for Zero {
    fn start_seek(mut self: Pin<&mut Self>, seek: SeekFrom) -> io::Result<()> {
        self.position = self.seek_position(seek)?;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl devmap_core::traits::tokio::Geometry for Zero {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }

    fn count(&mut self) -> Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(self.length)))
    }
}
