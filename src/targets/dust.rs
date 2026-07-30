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
    ///
    /// # Errors
    ///
    /// [`crate::Error::Usage`] if `block_size` is not a power of two in
    /// `512..=1_073_741_824`.
    pub fn new(device: DevId, offset_sectors: u64, block_size: u32) -> Result<Self, crate::Error> {
        if !(512..=1_073_741_824).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(crate::Error::Usage(format!(
                "dust block_size must be a power of two in 512..=1073741824, got {block_size}"
            )));
        }
        Ok(Dust { device, offset_sectors, block_size })
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
        write!(f, "{} {} {}", self.device, self.offset_sectors, self.block_size)
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
        let t = Dust::new(DevId::new(252, 1), 0, 512).expect("valid dust");
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }

    #[test]
    fn dust_rejects_bad_block_size() {
        // Not a power of two.
        assert!(matches!(Dust::new(DevId::new(252, 1), 0, 1000), Err(crate::Error::Usage(_))));
        // Below 512.
        assert!(matches!(Dust::new(DevId::new(252, 1), 0, 256), Err(crate::Error::Usage(_))));
        // Above the max.
        assert!(matches!(
            Dust::new(DevId::new(252, 1), 0, 2_147_483_648),
            Err(crate::Error::Usage(_))
        ));
    }

    #[test]
    fn dust_accepts_valid_block_size() {
        assert!(Dust::new(DevId::new(252, 1), 0, 512).is_ok());
        assert!(Dust::new(DevId::new(252, 1), 0, 4096).is_ok());
        assert!(Dust::new(DevId::new(252, 1), 0, 1_073_741_824).is_ok());
    }
}
