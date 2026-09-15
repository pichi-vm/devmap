// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr};

use super::ParseError;

/// Two values encoded as `a/b` in a device-mapper field.
///
/// Targets use this syntax for usage counts and progress. The values are not
/// reduced or interpreted as a mathematical ratio: zero and a first value
/// larger than the second are permitted. Their units and any relationship
/// between them belong to the target that interprets the field.
///
/// ```
/// use devmap_core::Fraction;
///
/// # fn main() -> Result<(), devmap_core::ParseError> {
/// let fraction: Fraction<u64> = "12/64".parse()?;
/// let (used, total) = fraction.into();
/// assert_eq!((used, total), (12, 64));
/// assert_eq!(Fraction::from((used, total)).to_string(), "12/64");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fraction<T>(T, T);

impl<T: FromStr> FromStr for Fraction<T> {
    type Err = ParseError;

    /// Splits at the first slash and parses both components without trimming.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the separator is absent or either component
    /// cannot be parsed as `T`. Integer components reject empty values, extra
    /// separators, whitespace, and overflow.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first, second) = s.split_once('/').ok_or(ParseError)?;
        Ok(Self(
            first.parse().map_err(|_| ParseError)?,
            second.parse().map_err(|_| ParseError)?,
        ))
    }
}

impl<T: fmt::Display> fmt::Display for Fraction<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

impl<T> From<(T, T)> for Fraction<T> {
    fn from((first, second): (T, T)) -> Self {
        Self(first, second)
    }
}

impl<T> From<Fraction<T>> for (T, T) {
    fn from(fraction: Fraction<T>) -> Self {
        (fraction.0, fraction.1)
    }
}
