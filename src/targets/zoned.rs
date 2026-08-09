// SPDX-License-Identifier: Apache-2.0

//! The `zoned` target: presents a zoned block device (ZBC/ZAC/ZNS) as a
//! regular block device.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// Exposes a zoned block device (ZBC/ZAC/ZNS) as a regular block
/// device. `device` must already be formatted with the kernel's
/// zoned-device metadata (via an external tool) before first use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Zoned {
    /// The underlying zoned block device.
    pub device: DevId,
}
impl Target for Zoned {
    const NAME: &'static str = "zoned";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Zoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.device)
    }
}
impl FromStr for Zoned {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // dm-zoned takes a regular cache device ahead of the zoned one in
        // its multi-device form. This type models the single-device form,
        // so a longer row is one it cannot represent.
        let mut p = Params::new(s);
        let target = Zoned {
            device: p.device()?,
        };
        p.end()?;
        Ok(target)
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
    fn zoned_renders_device_only() {
        let t = Zoned {
            device: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 zoned 252:1");
    }

    #[test]
    fn zoned_display_from_str_round_trips() {
        let original = Zoned {
            device: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(original.to_string().parse::<Zoned>(), Ok(original));
    }

    #[test]
    fn zoned_from_str_rejects_the_multi_device_form() {
        // A cache+zoned pair is a real dm-zoned table this type cannot
        // hold; rejecting beats silently dropping the cache device.
        assert!("252:1 252:2".parse::<Zoned>().is_err());
    }
}
