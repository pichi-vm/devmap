// SPDX-License-Identifier: Apache-2.0

//! The `zero` target: discards all writes and returns zeroes for all
//! reads.

use std::fmt;
use std::str::FromStr;

use devmap_core::{NoInfo, ParseError, Target as DmTarget};

/// Discards writes, returns zeroed reads. No parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target;
impl DmTarget for Target {
    const NAME: &'static str = "zero";
    type Table = Self;
    type Info = NoInfo;
}
impl fmt::Display for Target {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(Target)
        } else {
            Err(ParseError)
        }
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
    fn zero_kernel_abi_is_empty() {
        assert_eq!(line(0, 8, &Target), "0 8 zero");
    }

    #[test]
    fn zero_display_from_str_round_trips() {
        let original = Target;
        let params = original.to_string();
        assert_eq!(params.parse::<Target>(), Ok(original));
    }
}
