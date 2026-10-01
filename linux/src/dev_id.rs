// SPDX-License-Identifier: Apache-2.0

use crate::ParseError;
#[cfg(target_os = "linux")]
use std::io;
use std::{fmt, str::FromStr};

/// A Linux block-device number, expressed as `major:minor`.
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
}

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
impl TryFrom<std::fs::Metadata> for DevId {
    type Error = io::Error;

    fn try_from(metadata: std::fs::Metadata) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        if !metadata.file_type().is_block_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a block device",
            ));
        }
        let encoded = u32::try_from(metadata.rdev())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Self::from(encoded))
    }
}

#[cfg(target_os = "linux")]
#[cfg_attr(docsrs, doc(cfg(target_os = "linux")))]
impl TryFrom<std::fs::File> for DevId {
    type Error = io::Error;

    fn try_from(file: std::fs::File) -> io::Result<Self> {
        file.metadata()?.try_into()
    }
}

impl From<u32> for DevId {
    fn from(dev: u32) -> Self {
        Self {
            major: (dev >> 8) & 0xfff,
            minor: (dev & 0xff) | ((dev >> 12) & 0x000f_ff00),
        }
    }
}

impl From<DevId> for u64 {
    fn from(id: DevId) -> Self {
        u64::from((id.minor & 0xff) | (id.major << 8) | ((id.minor >> 8) << 20))
    }
}

impl FromStr for DevId {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = value.split_once(':').ok_or(ParseError)?;
        Self::new(major.parse()?, minor.parse()?).ok_or(ParseError)
    }
}

impl fmt::Display for DevId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}
