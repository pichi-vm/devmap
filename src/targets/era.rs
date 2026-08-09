// SPDX-License-Identifier: Apache-2.0

//! The `era` target: tracks which blocks of an origin device have changed
//! since a given "era", for incremental backup.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// Tracks which blocks of `origin` have changed since which "era", for
/// incremental backup. Era rollover/snapshot control is message-driven
/// — see [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Era {
    /// Device holding the era metadata (the change map).
    pub metadata: DevId,
    /// The origin device whose changes are tracked.
    pub origin: DevId,
    /// Tracking granularity, in 512-byte sectors per block.
    pub block_size: u32,
}
impl Target for Era {
    const NAME: &'static str = "era";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Era {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.metadata, self.origin, self.block_size)
    }
}
impl FromStr for Era {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let target = Era {
            metadata: p.device()?,
            origin: p.device()?,
            block_size: p.value()?,
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
    fn era_renders_metadata_origin_and_block_size() {
        let t = Era {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 era 252:1 252:2 128");
    }

    #[test]
    fn era_display_from_str_round_trips() {
        let original = Era {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(original.to_string().parse::<Era>(), Ok(original));
    }
}
