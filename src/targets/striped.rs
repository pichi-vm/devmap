// SPDX-License-Identifier: Apache-2.0

//! The `striped` target: spreads I/O across several devices in fixed-size
//! chunks (RAID0-style striping).

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// Concatenates several devices into one striped range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Striped {
    /// The chunk size in sectors.
    pub chunk_size_sectors: u32,
    /// The `(device, offset)` stripe pairs.
    pub stripes: Vec<(DevId, u64)>,
}
impl Target for Striped {
    const NAME: &'static str = "striped";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Striped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.stripes.len(), self.chunk_size_sectors)?;
        for (device, offset) in &self.stripes {
            write!(f, " {device} {offset}")?;
        }
        Ok(())
    }
}
impl FromStr for Striped {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let count: usize = p.value()?;
        let chunk_size_sectors = p.value()?;
        // Grown rather than reserved: `count` comes off the wire, so a
        // malformed row must not turn into a huge allocation. Running out
        // of tokens fails the pair read instead.
        let mut stripes = Vec::new();
        for _ in 0..count {
            stripes.push((p.device()?, p.value()?));
        }
        p.end()?;
        Ok(Striped {
            chunk_size_sectors,
            stripes,
        })
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
    fn striped_renders_stripe_count_and_pairs() {
        let t = Striped {
            chunk_size_sectors: 128,
            stripes: vec![
                (DevId::new(252, 1).unwrap(), 0),
                (DevId::new(252, 2).unwrap(), 0),
            ],
        };
        assert_eq!(line(0, 2048, &t), "0 2048 striped 2 128 252:1 0 252:2 0");
    }

    #[test]
    fn striped_display_from_str_round_trips() {
        let original = Striped {
            chunk_size_sectors: 128,
            stripes: vec![
                (DevId::new(252, 1).unwrap(), 0),
                (DevId::new(252, 2).unwrap(), 64),
            ],
        };
        assert_eq!(original.to_string().parse::<Striped>(), Ok(original));
    }

    #[test]
    fn striped_from_str_rejects_a_count_disagreeing_with_the_pairs() {
        assert!("3 128 252:1 0 252:2 0".parse::<Striped>().is_err());
        assert!("1 128 252:1 0 252:2 0".parse::<Striped>().is_err());
    }
}
