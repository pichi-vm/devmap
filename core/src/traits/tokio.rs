// SPDX-License-Identifier: Apache-2.0

//! Traits for Tokio asynchronous I/O.

use std::future::Future;
use std::io;
use std::num::NonZeroU32;
use std::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};
use std::pin::Pin;

use tokio::io::AsyncSeek;

use crate::{Region, Scaled};

/// Returns an asynchronous device's logical-block geometry.
///
/// Every device contains a finite number of nonzero-sized logical blocks and
/// begins at logical block zero. The product of [`Geometry::count`] and
/// [`Geometry::block_size`] must fit in `u64` bytes.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Geometry {
    /// Returns the logical block size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the geometry cannot be determined or is invalid.
    fn block_size(&self) -> io::Result<NonZeroU32>;

    /// Returns the number of logical blocks in the device.
    ///
    /// A successful call preserves the stream position.
    ///
    /// # Errors
    ///
    /// Returns an error if the geometry cannot be determined or the original
    /// stream position cannot be restored. Failure or cancellation may change
    /// it.
    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>>;

    /// Returns the complete byte extent, preserving position on success.
    ///
    /// # Errors
    ///
    /// Returns geometry inspection errors or `InvalidData` for an overflowing extent.
    /// Cancellation has the same positioning behavior as `count`.
    fn byte_size(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        let size = match self.block_size() {
            Ok(size) => u64::from(size.get()),
            Err(error) => return Box::pin(std::future::ready(Err(error))),
        };
        let count = self.count();
        Box::pin(async move {
            count
                .await?
                .checked_mul(size)
                .ok_or_else(|| io::ErrorKind::InvalidData.into())
        })
    }
}

impl<T: Geometry + ?Sized> Geometry for &mut T {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        T::count(self)
    }
}

impl<T: Geometry + ?Sized> Geometry for Box<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        T::count(self)
    }
}

/// Persists data accepted by an asynchronous I/O object.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait SyncData {
    /// Waits for previously completed data writes to become persistent.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence cannot be completed. Failure or
    /// cancellation does not indicate which earlier writes reached persistent
    /// storage.
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}

impl<T: SyncData + ?Sized> SyncData for &mut T {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        T::sync_data(self)
    }
}

impl<T: SyncData + ?Sized> SyncData for Box<T> {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        T::sync_data(self)
    }
}

/// Presents a device using larger logical blocks.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Scale: Geometry + Sized {
    /// Multiplies the logical block size while preserving the byte extent.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`crate::traits::std::Scale::scale`].
    fn scale(
        mut self,
        multiplier: NonZeroU32,
    ) -> impl Future<Output = io::Result<Scaled<Self>>> + Send
    where
        Self: Send,
    {
        async move {
            let block_size = self.block_size()?;
            let count = self.count().await?;
            Scaled::new(self, multiplier, block_size, count)
        }
    }
    /// Presents the device with logical blocks of `bytes` bytes.
    ///
    /// Preserves the complete byte extent and stream position. Equal sizes
    /// are allowed; sizes are never rounded and storage is not resized.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` unless the requested size is an exact
    /// power-of-two multiple of the current size and divides the extent.
    /// Other errors come from inspecting the device.
    fn scale_to(self, bytes: NonZeroU32) -> impl Future<Output = io::Result<Scaled<Self>>> + Send
    where
        Self: Send,
    {
        async move {
            let multiplier = Scaled::<Self>::multiplier_for(self.block_size()?, bytes)?;
            self.scale(multiplier).await
        }
    }
}

impl<T: Geometry> Scale for T {}

/// Creates a device over a logical-block range.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Slice<R>: Geometry + Sized {
    /// Returns a device whose block zero maps to the beginning of `range`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`crate::traits::std::Slice::slice`].
    fn slice(self, range: R) -> impl Future<Output = io::Result<Region<Self>>> + Send;
}

impl<T> Slice<(u64, u64)> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(mut self, (start, count): (u64, u64)) -> io::Result<Region<Self>> {
        let block_size = self.block_size()?;
        let device_count = self.count().await?;
        Region::from_async(self, start, count, device_count, block_size).await
    }
}

impl<T> Slice<Range<u64>> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(self, range: Range<u64>) -> io::Result<Region<Self>> {
        let count = range
            .end
            .checked_sub(range.start)
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (range.start, count)).await
    }
}

impl<T> Slice<RangeInclusive<u64>> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(self, range: RangeInclusive<u64>) -> io::Result<Region<Self>> {
        let (start, end) = range.into_inner();
        let count = end
            .checked_sub(start)
            .and_then(|count| count.checked_add(1))
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (start, count)).await
    }
}

impl<T> Slice<RangeTo<u64>> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(self, range: RangeTo<u64>) -> io::Result<Region<Self>> {
        <Self as Slice<(u64, u64)>>::slice(self, (0, range.end)).await
    }
}

impl<T> Slice<RangeToInclusive<u64>> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(self, range: RangeToInclusive<u64>) -> io::Result<Region<Self>> {
        let count = range
            .end
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (0, count)).await
    }
}

impl<T> Slice<RangeFrom<u64>> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(mut self, range: RangeFrom<u64>) -> io::Result<Region<Self>> {
        let device_count = self.count().await?;
        let count = device_count
            .checked_sub(range.start)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let block_size = self.block_size()?;
        Region::from_async(self, range.start, count, device_count, block_size).await
    }
}

impl<T> Slice<RangeFull> for T
where
    T: Geometry + AsyncSeek + Unpin + Send,
{
    async fn slice(mut self, _range: RangeFull) -> io::Result<Region<Self>> {
        let count = self.count().await?;
        let block_size = self.block_size()?;
        Region::from_async(self, 0, count, count, block_size).await
    }
}

/// Selects an aligned byte range without changing the device's block size.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait SliceBytes<R>: Geometry + Sized {
    /// Returns a zero-based view of a byte range.
    ///
    /// Bounds must fall on logical-block boundaries. Tuple input is
    /// `(start_bytes, length_bytes)`; inclusive ranges include their final byte.
    /// The view is finite even if the underlying writer can grow.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for misalignment, reversal, overflow or a range
    /// outside the device. Other errors come from inspecting or seeking it.
    fn slice_bytes(self, range: R) -> impl Future<Output = io::Result<Region<Self>>> + Send;
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<Range<u64>> for T {
    async fn slice_bytes(mut self, range: Range<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<RangeFrom<u64>> for T {
    async fn slice_bytes(mut self, range: RangeFrom<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<RangeFull> for T {
    async fn slice_bytes(mut self, range: RangeFull) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<RangeInclusive<u64>> for T {
    async fn slice_bytes(mut self, range: RangeInclusive<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<RangeTo<u64>> for T {
    async fn slice_bytes(mut self, range: RangeTo<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<RangeToInclusive<u64>> for T {
    async fn slice_bytes(mut self, range: RangeToInclusive<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count().await?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_async(self, start, length, count, block_size).await
    }
}

impl<T: Geometry + AsyncSeek + Unpin + Send> SliceBytes<(u64, u64)> for T {
    async fn slice_bytes(self, (start, length): (u64, u64)) -> io::Result<Region<Self>> {
        let end = start
            .checked_add(length)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.slice_bytes(start..end).await
    }
}
