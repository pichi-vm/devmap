// SPDX-License-Identifier: Apache-2.0

//! The `zero` target: discards all writes and returns zeroes for all
//! reads.

use std::fmt;
use std::str::FromStr;

use crate::table::{ParseError, RawInfo, Target};

/// Discards writes, returns zeroed reads. No parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Zero;
impl Target for Zero {
    const TYPE_NAME: &'static str = "zero";
    type Info = RawInfo;
}
impl fmt::Display for Zero {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl FromStr for Zero {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() { Ok(Zero) } else { Err(ParseError) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DevId;
    use crate::targets::snapshot;
    use crate::targets::{Error, Linear};

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn zero_kernel_abi_is_empty() {
        assert_eq!(line(0, 8, &Zero), "0 8 zero");
    }

    #[test]
    fn from_str_round_trips_trivial_targets() {
        assert_eq!("".parse::<Zero>(), Ok(Zero));
        assert_eq!("".parse::<Error>(), Ok(Error));
        assert_eq!(
            "252:5 5".parse::<Linear>(),
            Ok(Linear { device: DevId::new(252, 5), offset_sectors: 5 })
        );
        assert_eq!(
            "252:1".parse::<snapshot::Origin>(),
            Ok(snapshot::Origin { origin: DevId::new(252, 1) })
        );
    }

    #[test]
    fn zero_and_error_reject_non_empty_params() {
        assert!("junk".parse::<Zero>().is_err());
        assert!("junk".parse::<Error>().is_err());
    }
}
