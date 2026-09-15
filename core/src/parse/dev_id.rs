// SPDX-License-Identifier: Apache-2.0

use super::Error;
#[cfg(target_os = "linux")]
use std::io;
use std::{fmt, str::FromStr};

/// A Linux block-device number, expressed as `major:minor`.
///
/// Holds the 12-bit major and 20-bit minor accepted by device-mapper.
/// This value identifies a device; it does not open it or imply that it exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DevId {
    major: u32,
    minor: u32,
}

impl DevId {
    /// Constructs a number, or returns `None` if either component exceeds its field.
    pub const fn new(major: u32, minor: u32) -> Option<Self> {
        if major <= 0xfff && minor <= 0x000f_ffff {
            Some(Self { major, minor })
        } else {
            None
        }
    }
    /// Returns the major device number.
    pub const fn major(self) -> u32 {
        self.major
    }
    /// Returns the minor device number.
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Resolves a Linux block-device path without opening device-mapper.
    ///
    /// # Errors
    ///
    /// Returns a filesystem error, `InvalidInput` for a non-block device,
    /// or `InvalidData` for a number outside the supported field widths.
    #[cfg(target_os = "linux")]
    #[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
    pub fn from_path(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        let meta = std::fs::metadata(path)?;
        if !meta.file_type().is_block_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a block device",
            ));
        }
        let encoded = u32::try_from(meta.rdev())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Self::from(encoded))
    }
}
impl From<u32> for DevId {
    /// Decodes Linux's packed 32-bit device number.
    fn from(dev: u32) -> Self {
        Self {
            major: (dev >> 8) & 0xfff,
            minor: (dev & 0xff) | ((dev >> 12) & 0x000f_ff00),
        }
    }
}
impl From<DevId> for u64 {
    /// Encodes the number for device-mapper ioctl fields.
    fn from(id: DevId) -> Self {
        u64::from((id.minor & 0xff) | (id.major << 8) | ((id.minor >> 8) << 20))
    }
}
impl FromStr for DevId {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = value.split_once(':').ok_or(Error)?;
        Self::new(
            major.parse().map_err(|_| Error)?,
            minor.parse().map_err(|_| Error)?,
        )
        .ok_or(Error)
    }
}
impl fmt::Display for DevId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}
