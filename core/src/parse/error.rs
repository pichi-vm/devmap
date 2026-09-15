// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Malformed device-mapper text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed dm target params")
    }
}

impl std::error::Error for Error {}

impl From<std::num::ParseIntError> for Error {
    fn from(_: std::num::ParseIntError) -> Self {
        Self
    }
}
