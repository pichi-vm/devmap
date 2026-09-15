// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU32;

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

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
