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
pub struct Dust {
    /// The backing device.
    pub device: DevId,
    /// The starting offset in sectors.
    pub offset_sectors: u64,
    /// The block size in bytes.
    pub block_size: u32,
}
impl Target for Dust {
    const NAME: &'static str = "dust";
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
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {params}", T::NAME)
        }
    }

    #[test]
    fn dust_renders_device_offset_and_block_size() {
        let t = Dust {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
            block_size: 512,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }
}
