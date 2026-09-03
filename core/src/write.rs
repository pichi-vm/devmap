// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

use crate::BlockSize;

/// Writes complete fixed-size blocks by index.
pub trait WriteBlocks<const SIZE: usize> {
    /// Write block `index` in full.
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is outside the device or the underlying
    /// output cannot accept a complete block.
    fn write_block(&mut self, index: u64, block: &[u8; SIZE]) -> io::Result<()>;

    /// Flush buffered block writes.
    ///
    /// # Errors
    ///
    /// Returns the underlying output error.
    fn flush(&mut self) -> io::Result<()>;
}

impl<T: WriteBlocks<SIZE> + ?Sized, const SIZE: usize> WriteBlocks<SIZE> for &mut T {
    fn write_block(&mut self, index: u64, block: &[u8; SIZE]) -> io::Result<()> {
        (**self).write_block(index, block)
    }

    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
}

/// Writes complete runtime-sized blocks by index.
pub trait DynWriteBlocks: BlockSize {
    /// Write block `index` in full.
    ///
    /// `block.len()` must equal [`BlockSize::block_size`].
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `block` has the wrong
    /// length. Returns an error if `index` is outside the device or the
    /// underlying output cannot accept a complete block.
    fn write_block(&mut self, index: u64, block: &[u8]) -> io::Result<()>;

    /// Flush buffered block writes.
    ///
    /// # Errors
    ///
    /// Returns the underlying output error.
    fn flush(&mut self) -> io::Result<()>;
}

impl<T: DynWriteBlocks + ?Sized> DynWriteBlocks for &mut T {
    fn write_block(&mut self, index: u64, block: &[u8]) -> io::Result<()> {
        (**self).write_block(index, block)
    }

    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
}

/// Writes complete fixed-size blocks asynchronously by index.
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub trait AsyncWriteBlocks<const SIZE: usize> {
    /// Poll an exact write of block `index`.
    ///
    /// After this method returns [`Poll::Pending`], the caller must continue
    /// polling the same operation until it completes.
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8; SIZE],
    ) -> Poll<io::Result<()>>;

    /// Poll a flush of buffered block writes.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

#[cfg(feature = "futures-io")]
impl<T: AsyncWriteBlocks<SIZE> + Unpin + ?Sized, const SIZE: usize> AsyncWriteBlocks<SIZE>
    for &mut T
{
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8; SIZE],
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_write_block(cx, index, block)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_flush(cx)
    }
}

/// Writes complete runtime-sized blocks asynchronously by index.
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub trait DynAsyncWriteBlocks: BlockSize {
    /// Poll an exact write of block `index`.
    ///
    /// `block.len()` must equal [`BlockSize::block_size`]. After this method
    /// returns [`Poll::Pending`], the caller must continue polling the same
    /// operation until it completes.
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8],
    ) -> Poll<io::Result<()>>;

    /// Poll a flush of buffered block writes.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

#[cfg(feature = "futures-io")]
impl<T: DynAsyncWriteBlocks + Unpin + ?Sized> DynAsyncWriteBlocks for &mut T {
    fn poll_write_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &[u8],
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_write_block(cx, index, block)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_flush(cx)
    }
}
