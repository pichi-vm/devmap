// SPDX-License-Identifier: Apache-2.0

//! The Linux device-mapper `zero` target.

use std::fmt;
use std::str::FromStr;

use super::{Empty, EncodeError, Target, Version};
use crate::ParseError;
use crate::table::TableMode;
use crate::target::Parse;

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

    fn encode(&self, version: Version) -> Result<String, EncodeError> {
        if version.major != 1 {
            return Err(EncodeError { version });
        }
        Ok(String::new())
    }
}

impl Parse<TableMode> for ZeroTarget {
    type Error = ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        if version.major != 1 {
            return Err(ParseError);
        }
        let target: Self = text.parse()?;
        Ok(target)
    }
}
impl fmt::Display for ZeroTarget {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl FromStr for ZeroTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            Ok(ZeroTarget)
        } else {
            Err(ParseError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: Target>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.encode(Version::from([1, 0, 0])).unwrap();
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

    #[test]
    fn zero_rejects_unknown_major_versions() {
        let version = Version::from([2, 0, 0]);
        assert_eq!(ZeroTarget.encode(version), Err(EncodeError { version }));
        assert_eq!(
            <ZeroTarget as Parse<TableMode>>::parse("", version),
            Err(ParseError)
        );
    }
}
