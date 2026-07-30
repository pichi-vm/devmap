// SPDX-License-Identifier: Apache-2.0

//! The `error` target: fails all I/O to its range with an I/O error.

use std::fmt;
use std::str::FromStr;

use crate::table::{ParseError, RawInfo, Target};

/// Returns I/O errors for the whole range. No parameters. (The kernel
/// target is named `error`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error;
impl Target for Error {
    const TYPE_NAME: &'static str = "error";
    type Info = RawInfo;
}
impl fmt::Display for Error {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
impl FromStr for Error {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() { Ok(Error) } else { Err(ParseError) }
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
    fn error_target_kernel_abi_is_empty() {
        assert_eq!(line(0, 8, &Error), "0 8 error");
    }
}
