// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Malformed device-mapper target parameters or status text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed dm target params")
    }
}

impl std::error::Error for ParseError {}

impl From<std::num::ParseIntError> for ParseError {
    fn from(_: std::num::ParseIntError) -> Self {
        Self
    }
}
