// SPDX-License-Identifier: Apache-2.0

//! The `dust` target: injects read/write errors at chosen blocks for
//! fault-injection testing.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

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
    type Table = Self;
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
impl FromStr for Dust {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let target = Dust {
            device: p.device()?,
            offset_sectors: p.value()?,
            block_size: p.value()?,
        };
        p.end()?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    #[test]
    fn dust_renders_device_offset_and_block_size() {
        let t = Dust {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
            block_size: 512,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }

    #[test]
    fn dust_display_from_str_round_trips() {
        let original = Dust {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 64,
            block_size: 512,
        };
        assert_eq!(original.to_string().parse::<Dust>(), Ok(original));
    }

    #[test]
    fn dust_from_str_rejects_malformed_params() {
        for params in ["252:1 0", "252:1 0 512 9", "garbage 0 512", ""] {
            assert!(params.parse::<Dust>().is_err(), "should reject {params:?}");
        }
    }
}
