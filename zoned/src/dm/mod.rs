// SPDX-License-Identifier: Apache-2.0

//! The `zoned` target: presents a zoned block device (ZBC/ZAC/ZNS) as a
//! regular block device.

use std::fmt;
use std::io;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::TargetEndpoint;
use devmap_core::{Fraction, ParseError, Target as DmTarget};

/// Exposes a zoned block device (ZBC/ZAC/ZNS) as a regular block
/// device. `device` must already be formatted with the kernel's
/// zoned-device metadata before first use. This crate supplies metadata layout
/// generation and, on Linux, device-path formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The underlying zoned block device.
    pub device: DevId,
}
impl DmTarget for Target {
    const NAME: &'static str = "zoned";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.device)
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // dm-zoned takes a regular cache device ahead of the zoned one in
        // its multi-device form. This type models the single-device form,
        // so a longer row is one it cannot represent.
        let mut fields = s.split_whitespace();
        let target = Target {
            device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(target)
    }
}

/// The unmapped/total zone counts of one class of zones.
///
/// Encoded as two `u32` counts separated by `/`. Parsing checks the integer
/// syntax and range, not the relationship between the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ZoneUsage {
    /// Zones of this class not currently mapped to a chunk.
    pub unmapped: u32,
    /// Zones of this class in total.
    pub total: u32,
}

impl fmt::Display for ZoneUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Fraction::from((self.unmapped, self.total)).fmt(f)
    }
}

impl FromStr for ZoneUsage {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (unmapped, total) = s.parse::<Fraction<u32>>()?.into();
        Ok(Self { unmapped, total })
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

/// [`Target`]'s runtime status: how many zones exist and how many of each
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
        fn keyword(
            fields: &mut std::str::SplitWhitespace<'_>,
            expected: &str,
        ) -> Result<(), ParseError> {
            if fields.next().ok_or(ParseError)? == expected {
                Ok(())
            } else {
                Err(ParseError)
            }
        }

        let mut fields = s.split_whitespace();
        let total_zones = fields.next().ok_or(ParseError)?.parse()?;
        keyword(&mut fields, "zones")?;
        let cache = fields.next().ok_or(ParseError)?.parse()?;
        keyword(&mut fields, "cache")?;

        // The per-device pairs repeat to the end of the line; a cache-only
        // first device contributes none, so an empty list is valid.
        let mut devices = Vec::new();
        while let Some(random) = fields.next() {
            let random = random.parse()?;
            keyword(&mut fields, "random")?;
            let sequential = fields.next().ok_or(ParseError)?.parse()?;
            keyword(&mut fields, "sequential")?;
            devices.push(DeviceZones { random, sequential });
        }
        Ok(Info {
            total_zones,
            cache,
            devices,
        })
    }
}

/// Messages to a live [`Target`], via
/// a backend's typed target endpoint.
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `reclaim` — trigger zone reclaim, migrating data out of buffer
    /// zones so they can be freed for reuse.
    fn reclaim(&self) -> io::Result<()> {
        self.message("reclaim").map(drop)
    }
}
impl<T: TargetEndpoint<Target = Target> + ?Sized> Commands for T {}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: DmTarget + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    #[test]
    fn zoned_renders_device_only() {
        let t = Target {
            device: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 zoned 252:1");
    }

    #[test]
    fn zoned_display_from_str_round_trips() {
        let original = Target {
            device: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }

    #[test]
    fn zoned_from_str_rejects_the_multi_device_form() {
        // A cache+zoned pair is a real dm-zoned table this type cannot
        // hold; rejecting beats silently dropping the cache device.
        assert!("252:1 252:2".parse::<Target>().is_err());
    }
}
