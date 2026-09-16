// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io, num::NonZeroU32, str::FromStr};

/// A power-of-two block size with a minimum base-two exponent.
///
/// Accepts byte sizes from 2^`MIN` through 2³⁰. `MIN` defaults to 9
/// (512 bytes); `BlockSize<0>` permits byte-sized blocks. Construction,
/// parsing, and display use bytes. Formats may impose narrower limits.
///
/// ```
/// use devmap_core::BlockSize;
///
/// # fn main() -> std::io::Result<()> {
/// let byte = BlockSize::<0>::try_from(1u32)?;
/// assert_eq!(u32::from(byte), 1);
/// assert!(BlockSize::<12>::try_from(512u32).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockSize<const MIN: u32 = 9>(NonZeroU32);

impl<const MIN: u32> Default for BlockSize<MIN> {
    /// Returns 4096 bytes, or 2^`MIN` bytes when `MIN` exceeds 12.
    ///
    /// A minimum exponent above 30 has no representable default and fails at compile time.
    ///
    /// ```compile_fail
    /// use devmap_core::BlockSize;
    /// let _ = BlockSize::<31>::default();
    /// ```
    fn default() -> Self {
        Self(
            const {
                assert!(MIN <= 30, "block-size minimum exceeds the maximum");
                let bytes = 1u32 << if MIN > 12 { MIN } else { 12 };
                NonZeroU32::new(bytes).unwrap()
            },
        )
    }
}

impl<const MIN: u32> TryFrom<u32> for BlockSize<MIN> {
    type Error = io::Error;
    fn try_from(bytes: u32) -> io::Result<Self> {
        if !bytes.is_power_of_two() || bytes.trailing_zeros() < MIN || bytes > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid block size",
            ));
        }
        NonZeroU32::new(bytes)
            .map(Self)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }
}

impl<const MIN: u32> TryFrom<NonZeroU32> for BlockSize<MIN> {
    type Error = io::Error;
    fn try_from(bytes: NonZeroU32) -> io::Result<Self> {
        Self::try_from(bytes.get())
    }
}

impl<const MIN: u32> From<BlockSize<MIN>> for u32 {
    fn from(size: BlockSize<MIN>) -> Self {
        size.0.get()
    }
}
impl<const MIN: u32> From<BlockSize<MIN>> for NonZeroU32 {
    fn from(size: BlockSize<MIN>) -> Self {
        size.0
    }
}
impl<const MIN: u32> FromStr for BlockSize<MIN> {
    type Err = io::Error;
    fn from_str(value: &str) -> io::Result<Self> {
        Self::try_from(
            value
                .parse::<u32>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        )
    }
}
impl<const MIN: u32> fmt::Display for BlockSize<MIN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
