// SPDX-License-Identifier: Apache-2.0

//! The `dust` target: injects read/write errors at chosen blocks for
//! fault-injection testing.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// Injects read/write errors at specific blocks, for fault-injection
/// testing. Bad-block management is message-driven — see
/// [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Dust {
    device: DevId,
    offset_sectors: u64,
    block_size: u32,
}
impl Dust {
    /// Construct a [`Dust`].
    pub fn new(device: DevId, offset_sectors: u64, block_size: u32) -> Self {
        Dust {
            device,
            offset_sectors,
            block_size,
        }
    }

    /// The backing device.
    #[must_use]
    pub fn device(&self) -> DevId {
        self.device
    }
    /// The starting offset in sectors.
    #[must_use]
    pub fn offset_sectors(&self) -> u64 {
        self.offset_sectors
    }
    /// The block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
}
impl Target for Dust {
    const TYPE_NAME: &'static str = "dust";
    type Info = RawInfo;
}
impl fmt::Display for Dust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.device, self.offset_sectors, self.block_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn dust_renders_device_offset_and_block_size() {
        let t = Dust::new(DevId::new(252, 1).unwrap(), 0, 512);
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }
}
