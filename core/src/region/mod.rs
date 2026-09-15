// SPDX-License-Identifier: Apache-2.0

use std::io::{self, SeekFrom};
use std::num::NonZeroU32;

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

/// A bounded, zero-based view of a device.
///
/// Create with [`Slice`](crate::traits::std::Slice) or
/// [`SliceBytes`](crate::traits::std::SliceBytes), or their Tokio counterparts.
/// Byte offset zero maps to the selected range's start. Reads and writes stop
/// at its end; the underlying storage is not resized.
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
