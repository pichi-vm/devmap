// SPDX-License-Identifier: Apache-2.0

//! The `zoned` target: presents a zoned block device (ZBC/ZAC/ZNS) as a
//! regular block device.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// Exposes a zoned block device (ZBC/ZAC/ZNS) as a regular block
/// device. `device` must already be formatted with the kernel's
/// zoned-device metadata (via an external tool) before first use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Zoned {
    /// The underlying zoned block device.
    pub device: DevId,
}
impl Target for Zoned {
    const TYPE_NAME: &'static str = "zoned";
    type Info = RawInfo;
}
impl fmt::Display for Zoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.device)
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
    fn zoned_renders_device_only() {
        let t = Zoned {
            device: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 zoned 252:1");
    }
}
