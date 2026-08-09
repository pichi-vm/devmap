// SPDX-License-Identifier: Apache-2.0

//! The `thin` target: a single thin-provisioned volume backed by a
//! thin-pool.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target, parse_device};

/// One provisioned volume inside a [`crate::targets::ThinPool`]. `dev_id` must already
/// exist in the pool (created via a `create_thin`/`create_snap`
/// message — see [`crate::Device::message`]) before this table line can
/// be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Thin {
    /// The backing thin-pool device.
    pub pool: DevId,
    /// The thin device id within the pool.
    pub dev_id: u32,
    /// The external origin device, if any.
    pub external_origin: Option<DevId>,
}
impl Target for Thin {
    const NAME: &'static str = "thin";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Thin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.pool, self.dev_id)?;
        if let Some(external_origin) = self.external_origin {
            write!(f, " {external_origin}")?;
        }
        Ok(())
    }
}
impl FromStr for Thin {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let pool = p.device()?;
        let dev_id = p.value()?;
        let external_origin = match p.optional() {
            Some(token) => Some(parse_device(token).ok_or(ParseError)?),
            None => None,
        };
        p.end()?;
        Ok(Thin {
            pool,
            dev_id,
            external_origin,
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
    fn thin_renders_without_external_origin() {
        let t = Thin {
            pool: DevId::new(252, 1).unwrap(),
            dev_id: 7,
            external_origin: None,
        };
        assert_eq!(line(0, 1024, &t), "0 1024 thin 252:1 7");
    }

    #[test]
    fn thin_renders_with_external_origin() {
        let t = Thin {
            pool: DevId::new(252, 1).unwrap(),
            dev_id: 7,
            external_origin: Some(DevId::new(252, 9).unwrap()),
        };
        assert_eq!(line(0, 1024, &t), "0 1024 thin 252:1 7 252:9");
    }

    #[test]
    fn thin_display_from_str_round_trips_both_forms() {
        for external_origin in [None, Some(DevId::new(252, 9).unwrap())] {
            let original = Thin {
                pool: DevId::new(252, 1).unwrap(),
                dev_id: 7,
                external_origin,
            };
            assert_eq!(original.to_string().parse::<Thin>(), Ok(original));
        }
    }
}
