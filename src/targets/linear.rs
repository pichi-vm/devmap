// SPDX-License-Identifier: Apache-2.0

//! The `linear` target: maps a range straight through to another device at
//! a fixed sector offset.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{ParseError, RawInfo, Target, parse_device};

/// Maps straight through to another device at a sector offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Linear {
    /// The underlying device this range maps onto.
    pub device: DevId,
    /// Starting offset into `device`, in 512-byte sectors.
    pub offset_sectors: u64,
}
impl Target for Linear {
    const TYPE_NAME: &'static str = "linear";
    type Info = RawInfo;
}
impl fmt::Display for Linear {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.offset_sectors)
    }
}
impl FromStr for Linear {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split_whitespace();
        let device = it.next().and_then(parse_device).ok_or(ParseError)?;
        let offset_sectors = it.next().ok_or(ParseError)?.parse().map_err(|_| ParseError)?;
        if it.next().is_some() {
            return Err(ParseError);
        }
        Ok(Linear { device, offset_sectors })
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
    fn linear_renders_device_and_offset() {
        let t = Linear { device: DevId::new(252, 5), offset_sectors: 5 };
        assert_eq!(line(0, 1024, &t), "0 1024 linear 252:5 5");
    }

    #[test]
    fn linear_from_str_rejects_malformed_params() {
        for params in ["252:5 5 6" /* trailing */, "garbage" /* no colon */, "252:x 5" /* bad minor */, ""] {
            assert!(params.parse::<Linear>().is_err(), "linear should reject {params:?}");
        }
    }
}
