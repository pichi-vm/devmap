// SPDX-License-Identifier: Apache-2.0

use super::Version;
use crate::ParseError;
use crate::table::Mode;
use crate::target::Parse;
use std::{fmt, str::FromStr};

/// An empty target parameter or status field, valid in both table and info modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Empty;

impl FromStr for Empty {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Ok(Self)
        } else {
            Err(ParseError)
        }
    }
}

impl<M: Mode> Parse<M> for Empty {
    type Error = ParseError;

    fn parse(text: &str, _: Version) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl fmt::Display for Empty {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
