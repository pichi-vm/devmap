// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Error returned when a device-mapper field, table, or status string does not
/// match its expected grammar.
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
