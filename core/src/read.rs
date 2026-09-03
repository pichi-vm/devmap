// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "futures-io")]
use std::pin::Pin;
#[cfg(feature = "futures-io")]
use std::task::{Context, Poll};

use crate::BlockSize;

/// Reads complete fixed-size blocks by index.
pub trait ReadBlocks<const SIZE: usize> {
    /// Read block `index` in full.
    ///
    /// # Errors
    ///
    /// Returns an error if `index` is outside the device or the underlying
    /// input cannot provide a complete block.
    fn read_block(&mut self, index: u64, block: &mut [u8; SIZE]) -> io::Result<()>;
}

impl<T: ReadBlocks<SIZE> + ?Sized, const SIZE: usize> ReadBlocks<SIZE> for &mut T {
    fn read_block(&mut self, index: u64, block: &mut [u8; SIZE]) -> io::Result<()> {
        (**self).read_block(index, block)
    }
}

/// Reads complete runtime-sized blocks by index.
pub trait DynReadBlocks: BlockSize {
    /// Read block `index` in full.
    ///
    /// `block.len()` must equal [`BlockSize::block_size`].
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `block` has the wrong
    /// length. Returns an error if `index` is outside the device or the
    /// underlying input cannot provide a complete block.
    fn read_block(&mut self, index: u64, block: &mut [u8]) -> io::Result<()>;
}

impl<T: DynReadBlocks + ?Sized> DynReadBlocks for &mut T {
    fn read_block(&mut self, index: u64, block: &mut [u8]) -> io::Result<()> {
        (**self).read_block(index, block)
    }
}

/// Reads complete fixed-size blocks asynchronously by index.
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub trait AsyncReadBlocks<const SIZE: usize> {
    /// Poll an exact read of block `index`.
    ///
    /// After this method returns [`Poll::Pending`], the caller must continue
    /// polling the same operation until it completes.
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8; SIZE],
    ) -> Poll<io::Result<()>>;
}

#[cfg(feature = "futures-io")]
impl<T: AsyncReadBlocks<SIZE> + Unpin + ?Sized, const SIZE: usize> AsyncReadBlocks<SIZE>
    for &mut T
{
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8; SIZE],
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_read_block(cx, index, block)
    }
}

/// Reads complete runtime-sized blocks asynchronously by index.
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub trait DynAsyncReadBlocks: BlockSize {
    /// Poll an exact read of block `index`.
    ///
    /// `block.len()` must equal [`BlockSize::block_size`]. After this method
    /// returns [`Poll::Pending`], the caller must continue polling the same
    /// operation until it completes.
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8],
    ) -> Poll<io::Result<()>>;
}

#[cfg(feature = "futures-io")]
impl<T: DynAsyncReadBlocks + Unpin + ?Sized> DynAsyncReadBlocks for &mut T {
    fn poll_read_block(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        index: u64,
        block: &mut [u8],
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_read_block(cx, index, block)
    }
}
