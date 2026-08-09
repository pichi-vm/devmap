// SPDX-License-Identifier: Apache-2.0

//! The `zoned` target: presents a zoned block device (ZBC/ZAC/ZNS) as a
//! regular block device.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, Target};

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
    type Info = Info;
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

/// The unmapped/total zone counts of one class of zones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ZoneUsage {
    /// Zones of this class not currently mapped to a chunk.
    pub unmapped: u32,
    /// Zones of this class in total.
    pub total: u32,
}

impl fmt::Display for ZoneUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.unmapped, self.total)
    }
}

/// The random and sequential zone usage of one backing device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DeviceZones {
    /// Randomly-writable zones on this device.
    pub random: ZoneUsage,
    /// Sequential-write-required zones on this device.
    pub sequential: ZoneUsage,
}

/// [`Zoned`]'s runtime status: how many zones exist and how many of each
/// class are still unmapped.
///
/// The kernel writes this with inline keywords rather than as positional
/// fields — `4096 zones 0/0 cache 512/512 random 3584/3584 sequential` —
/// and repeats the random/sequential pair per backing device, omitting
/// the first device's pair when it is cache-only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Zones across all backing devices.
    pub total_zones: u32,
    /// Cache zones, on the regular device fronting the zoned one.
    pub cache: ZoneUsage,
    /// Per-backing-device zone usage, in device order.
    pub devices: Vec<DeviceZones>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} zones {} cache", self.total_zones, self.cache)?;
        for device in &self.devices {
            write!(
                f,
                " {} random {} sequential",
                device.random, device.sequential
            )?;
        }
        Ok(())
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn usage(p: &mut Params<'_>) -> Result<ZoneUsage, ParseError> {
            let (unmapped, total) = p.fraction()?;
            Ok(ZoneUsage { unmapped, total })
        }
        fn keyword(p: &mut Params<'_>, expected: &str) -> Result<(), ParseError> {
            if p.token()? == expected {
                Ok(())
            } else {
                Err(ParseError)
            }
        }

        let mut p = Params::new(s);
        let total_zones = p.value()?;
        keyword(&mut p, "zones")?;
        let cache = usage(&mut p)?;
        keyword(&mut p, "cache")?;

        // The per-device pairs repeat to the end of the line; a cache-only
        // first device contributes none, so an empty list is valid.
        let mut devices = Vec::new();
        while p.remaining() > 0 {
            let random = usage(&mut p)?;
            keyword(&mut p, "random")?;
            let sequential = usage(&mut p)?;
            keyword(&mut p, "sequential")?;
            devices.push(DeviceZones { random, sequential });
        }
        Ok(Info {
            total_zones,
            cache,
            devices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

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
