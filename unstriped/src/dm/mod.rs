// SPDX-License-Identifier: Apache-2.0

//! The `unstriped` target: exposes a single stripe of an existing
//! striped/RAID0 mapping as its own device.

use std::fmt;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::{NoInfo, ParseError, Target as DmTarget};

/// Exposes one stripe of an existing striped/RAID0 mapping as its own
/// device, for per-stripe `QoS` isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The total number of stripes in the underlying mapping.
    ///
    /// The kernel enforces the value rules on table load: `stripes` and
    /// `chunk_size_sectors` must be nonzero, and `stripe_index` must be
    /// less than `stripes`.
    pub stripes: u32,
    /// The chunk size in sectors.
    pub chunk_size_sectors: u32,
    /// The index of the exposed stripe.
    pub stripe_index: u32,
    /// The backing device.
    pub device: DevId,
    /// The starting offset in sectors.
    pub offset_sectors: u64,
}
impl DmTarget for Target {
    const NAME: &'static str = "unstriped";
    type Table = Self;
    type Info = NoInfo;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.stripes,
            self.chunk_size_sectors,
            self.stripe_index,
            self.device,
            self.offset_sectors
        )
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let target = Target {
            stripes: fields.next().ok_or(ParseError)?.parse()?,
            chunk_size_sectors: fields.next().ok_or(ParseError)?.parse()?,
            stripe_index: fields.next().ok_or(ParseError)?.parse()?,
            device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            offset_sectors: fields.next().ok_or(ParseError)?.parse()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(target)
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
    fn unstriped_renders_all_fields() {
        let t = Target {
            stripes: 2,
            chunk_size_sectors: 256,
            stripe_index: 0,
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
        };
        assert_eq!(line(0, 512, &t), "0 512 unstriped 2 256 0 252:1 0");
    }

    #[test]
    fn unstriped_display_from_str_round_trips() {
        let original = Target {
            stripes: 2,
            chunk_size_sectors: 256,
            stripe_index: 1,
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 8,
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }
}
