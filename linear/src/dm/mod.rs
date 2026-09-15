// SPDX-License-Identifier: Apache-2.0

//! The `linear` target: maps a range straight through to another device at
//! a fixed sector offset.

use std::fmt;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::{NoInfo, ParseError, Target as DmTarget};

/// Maps straight through to another device at a sector offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The underlying device this range maps onto.
    pub device: DevId,
    /// Starting offset into `device`, in 512-byte sectors.
    pub offset_sectors: u64,
}
impl DmTarget for Target {
    const NAME: &'static str = "linear";
    type Table = Self;
    type Info = NoInfo;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.offset_sectors)
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split_whitespace();
        let device = it
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(ParseError)?;
        let offset_sectors = it
            .next()
            .ok_or(ParseError)?
            .parse()
            .map_err(|_| ParseError)?;
        if it.next().is_some() {
            return Err(ParseError);
        }
        Ok(Target {
            device,
            offset_sectors,
        })
    }
}

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
    fn linear_renders_device_and_offset() {
        let t = Target {
            device: DevId::new(252, 5).unwrap(),
            offset_sectors: 5,
        };
        assert_eq!(line(0, 1024, &t), "0 1024 linear 252:5 5");
    }

    #[test]
    fn linear_display_from_str_round_trips() {
        let original = Target {
            device: DevId::new(252, 5).unwrap(),
            offset_sectors: 42,
        };
        let params = original.to_string();
        assert_eq!(params.parse::<Target>(), Ok(original));
    }

    #[test]
    fn linear_from_str_rejects_malformed_params() {
        for params in [
            "252:5 5 6", /* trailing */
            "garbage",   /* no colon */
            "252:x 5",   /* bad minor */
            "",
        ] {
            assert!(
                params.parse::<Target>().is_err(),
                "linear should reject {params:?}"
            );
        }
    }
}
