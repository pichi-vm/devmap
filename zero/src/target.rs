// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::str::FromStr;

use devmap_core::Target;
use devmap_core::parse::{Empty, Error};

/// The Linux device-mapper `zero` target.
///
/// Reads return zeroes; writes are discarded. The table row supplies its size.
/// Parameters are empty: parsing accepts only `""`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZeroTarget;
impl Target for ZeroTarget {
    const NAME: &'static str = "zero";
    type Table = Self;
    type Info = Empty;
}
impl fmt::Display for ZeroTarget {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl FromStr for ZeroTarget {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(ZeroTarget)
        } else {
            Err(Error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: Target + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    #[test]
    fn zero_kernel_abi_is_empty() {
        assert_eq!(line(0, 8, &ZeroTarget), "0 8 zero");
    }

    #[test]
    fn zero_display_from_str_round_trips() {
        let original = ZeroTarget;
        let params = original.to_string();
        assert_eq!(params.parse::<ZeroTarget>(), Ok(original));
    }
}
