// SPDX-License-Identifier: Apache-2.0

//! Traits for standard-library synchronous I/O.

use std::io::{self, Seek};
use std::num::NonZeroU32;
use std::ops::{Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

use crate::{Region, Scaled};

/// Returns a device's logical-block geometry.
///
/// Every device contains a finite number of nonzero-sized logical blocks and
/// begins at logical block zero. The product of [`Geometry::count`] and
/// [`Geometry::block_size`] must fit in `u64` bytes.
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
    /// stream position cannot be restored. A failed call may change it.
    fn count(&mut self) -> io::Result<u64>;

    /// Returns the complete byte extent, preserving position on success.
    ///
    /// # Errors
    ///
    /// Returns geometry inspection errors or `InvalidData` for an overflowing extent.
    fn byte_size(&mut self) -> io::Result<u64> {
        let size = u64::from(self.block_size()?.get());
        self.count()?
            .checked_mul(size)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }
}

impl<T: Geometry + ?Sized> Geometry for &mut T {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> io::Result<u64> {
        T::count(self)
    }
}

impl<T: Geometry + ?Sized> Geometry for Box<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> io::Result<u64> {
        T::count(self)
    }
}

/// Persists data accepted by a synchronous I/O object.
///
/// On success, writes completed before the call no longer depend on volatile
/// caches when the underlying object has persistent storage. This is stronger
/// than [`io::Write::flush`], which only drains writer buffering. Objects
/// without a persistence boundary may implement this operation as a no-op.
pub trait SyncData {
    /// Waits for previously completed data writes to become persistent.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence cannot be completed. Failure does not
    /// indicate which earlier writes reached persistent storage.
    fn sync_data(&mut self) -> io::Result<()>;
}

impl<T: SyncData + ?Sized> SyncData for &mut T {
    fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self)
    }
}

impl<T: SyncData + ?Sized> SyncData for Box<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self)
    }
}

/// Presents a device using larger logical blocks.
pub trait Scale: Geometry + Sized {
    /// Multiplies the logical block size while preserving the byte extent.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] unless `multiplier` is a power
    /// of two, the block size can be multiplied by it, and the block count can
    /// be divided by it exactly. Other errors come from inspecting the device.
    fn scale(mut self, multiplier: NonZeroU32) -> io::Result<Scaled<Self>> {
        let block_size = self.block_size()?;
        let count = self.count()?;
        Scaled::new(self, multiplier, block_size, count)
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
    fn scale_to(self, bytes: NonZeroU32) -> io::Result<Scaled<Self>> {
        let multiplier = Scaled::<Self>::multiplier_for(self.block_size()?, bytes)?;
        self.scale(multiplier)
    }
}

impl<T: Geometry> Scale for T {}

/// Creates a device over a logical-block range.
pub trait Slice<R>: Geometry + Sized {
    /// Returns a device whose block zero maps to the beginning of `range`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the range is reversed,
    /// overflows, or extends beyond the device. Other errors come from
    /// inspecting or positioning the device.
    fn slice(self, range: R) -> io::Result<Region<Self>>;
}

impl<T: Geometry + Seek> Slice<(u64, u64)> for T {
    fn slice(mut self, (start, count): (u64, u64)) -> io::Result<Region<Self>> {
        let block_size = self.block_size()?;
        let device_count = self.count()?;
        Region::from_sync(self, start, count, device_count, block_size)
    }
}

impl<T: Geometry + Seek> Slice<Range<u64>> for T {
    fn slice(self, range: Range<u64>) -> io::Result<Region<Self>> {
        let count = range
            .end
            .checked_sub(range.start)
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (range.start, count))
    }
}

impl<T: Geometry + Seek> Slice<RangeInclusive<u64>> for T {
    fn slice(self, range: RangeInclusive<u64>) -> io::Result<Region<Self>> {
        let (start, end) = range.into_inner();
        let count = end
            .checked_sub(start)
            .and_then(|count| count.checked_add(1))
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (start, count))
    }
}

impl<T: Geometry + Seek> Slice<RangeTo<u64>> for T {
    fn slice(self, range: RangeTo<u64>) -> io::Result<Region<Self>> {
        <Self as Slice<(u64, u64)>>::slice(self, (0, range.end))
    }
}

impl<T: Geometry + Seek> Slice<RangeToInclusive<u64>> for T {
    fn slice(self, range: RangeToInclusive<u64>) -> io::Result<Region<Self>> {
        let count = range
            .end
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidInput)?;
        <Self as Slice<(u64, u64)>>::slice(self, (0, count))
    }
}

impl<T: Geometry + Seek> Slice<RangeFrom<u64>> for T {
    fn slice(mut self, range: RangeFrom<u64>) -> io::Result<Region<Self>> {
        let device_count = self.count()?;
        let count = device_count
            .checked_sub(range.start)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let block_size = self.block_size()?;
        Region::from_sync(self, range.start, count, device_count, block_size)
    }
}

impl<T: Geometry + Seek> Slice<RangeFull> for T {
    fn slice(mut self, _range: RangeFull) -> io::Result<Region<Self>> {
        let count = self.count()?;
        let block_size = self.block_size()?;
        Region::from_sync(self, 0, count, count, block_size)
    }
}

/// Selects an aligned byte range without changing the device's block size.
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
    fn slice_bytes(self, range: R) -> io::Result<Region<Self>>;
}

impl<T: Geometry + Seek> SliceBytes<Range<u64>> for T {
    fn slice_bytes(mut self, range: Range<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<RangeFrom<u64>> for T {
    fn slice_bytes(mut self, range: RangeFrom<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<RangeFull> for T {
    fn slice_bytes(mut self, range: RangeFull) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<RangeInclusive<u64>> for T {
    fn slice_bytes(mut self, range: RangeInclusive<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<RangeTo<u64>> for T {
    fn slice_bytes(mut self, range: RangeTo<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<RangeToInclusive<u64>> for T {
    fn slice_bytes(mut self, range: RangeToInclusive<u64>) -> io::Result<Region<Self>> {
        use std::ops::RangeBounds as _;
        let block_size = self.block_size()?;
        let count = self.count()?;
        let (start, length) = Region::<T>::byte_range(
            range.start_bound().cloned(),
            range.end_bound().cloned(),
            count,
            block_size,
        )?;
        Region::from_sync(self, start, length, count, block_size)
    }
}

impl<T: Geometry + Seek> SliceBytes<(u64, u64)> for T {
    fn slice_bytes(self, (start, length): (u64, u64)) -> io::Result<Region<Self>> {
        let end = start
            .checked_add(length)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.slice_bytes(start..end)
    }
}
