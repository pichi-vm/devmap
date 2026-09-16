// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io, num::NonZeroU32, str::FromStr};

/// A power-of-two block size with a compile-time minimum, in bytes.
///
/// Accepts nonzero powers of two from `MIN` through 2³⁰ bytes. The minimum
/// defaults to 512; `BlockSize<1>` also permits byte-sized blocks.
/// Formats may impose narrower limits.
///
/// ```
/// use devmap_core::BlockSize;
///
/// # fn main() -> std::io::Result<()> {
/// let byte = BlockSize::<1>::try_from(1u32)?;
/// assert_eq!(u32::from(byte), 1);
/// assert!(BlockSize::<4096>::try_from(512u32).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockSize<const MIN: u32 = 512>(NonZeroU32);

impl<const MIN: u32> Default for BlockSize<MIN> {
    /// Returns 4096 bytes, or the smallest permitted size if `MIN` is larger.
    ///
    /// A minimum above 2³⁰ has no representable default and fails at compile time.
    ///
    /// ```compile_fail
    /// use devmap_core::BlockSize;
    /// let _ = BlockSize::<{ 1 << 31 }>::default();
    /// ```
    fn default() -> Self {
        Self(
            const {
                assert!(MIN <= 1 << 30, "block-size minimum exceeds the maximum");
                let bytes = if MIN > 4096 {
                    MIN.next_power_of_two()
                } else {
                    4096
                };
                NonZeroU32::new(bytes).unwrap()
            },
        )
    }
}

impl<const MIN: u32> TryFrom<u32> for BlockSize<MIN> {
    type Error = io::Error;
    fn try_from(bytes: u32) -> io::Result<Self> {
        if bytes < MIN || !bytes.is_power_of_two() || bytes > i32::MAX as u32 {
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
