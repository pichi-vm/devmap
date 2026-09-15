// SPDX-License-Identifier: Apache-2.0

use super::Error;
use std::{fmt, str::FromStr};

/// An empty parameter or status field.
///
/// Accepts empty or whitespace-only input; rejects other text. Formats as an
/// empty string. Use as [`Target::Info`](crate::Target::Info) for targets with
/// no runtime status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Empty;

impl FromStr for Empty {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Ok(Empty)
        } else {
            Err(Error)
        }
    }
}

impl fmt::Display for Empty {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
