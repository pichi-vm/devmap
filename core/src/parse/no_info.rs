// SPDX-License-Identifier: Apache-2.0

use super::Error;
use std::{fmt, str::FromStr};

/// The [`Target::Info`](crate::Target::Info) of a target with no runtime status: the kernel
/// emits an empty params field for it.
///
/// Parsing accepts empty or whitespace-only text and rejects other status
/// text. Formatting emits an empty string. Use [`String`] as the associated
/// status type when arbitrary text should be retained without validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NoInfo;

impl FromStr for NoInfo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Ok(NoInfo)
        } else {
            Err(Error)
        }
    }
}

impl fmt::Display for NoInfo {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}
