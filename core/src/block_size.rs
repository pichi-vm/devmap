// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io, num::NonZeroU32, str::FromStr};

/// A power-of-two size for sector-based blocks, in bytes.
///
/// Accepts 512 through 2³⁰ bytes. The default is 4096 bytes.
/// Formats may impose narrower limits; general byte-stream geometry uses
/// [`NonZeroU32`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockSize(NonZeroU32);

impl Default for BlockSize {
    fn default() -> Self {
        Self(NonZeroU32::new(4096).unwrap())
    }
}

impl TryFrom<u32> for BlockSize {
    type Error = io::Error;
    fn try_from(bytes: u32) -> io::Result<Self> {
        if bytes < 512 || !bytes.is_power_of_two() || bytes > i32::MAX as u32 {
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

impl TryFrom<NonZeroU32> for BlockSize {
    type Error = io::Error;
    fn try_from(bytes: NonZeroU32) -> io::Result<Self> {
        Self::try_from(bytes.get())
    }
}

impl From<BlockSize> for u32 {
    fn from(size: BlockSize) -> Self {
        size.0.get()
    }
}
impl From<BlockSize> for NonZeroU32 {
    fn from(size: BlockSize) -> Self {
        size.0
    }
}
impl FromStr for BlockSize {
    type Err = io::Error;
    fn from_str(value: &str) -> io::Result<Self> {
        Self::try_from(
            value
                .parse::<u32>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        )
    }
}
impl fmt::Display for BlockSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
