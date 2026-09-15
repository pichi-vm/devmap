// SPDX-License-Identifier: Apache-2.0

use super::Target;
use std::{fmt::Display, io};

/// Adds target rows to a table with explicit lengths and access mode.
///
/// Lets format code add correctly sized rows and request read-only access
/// without encoding backend-specific table buffers. Loading and activation
/// remain operations of the concrete backend.
pub trait TableBuilder: Sized {
    /// Sets read-only access for the whole table.
    #[must_use]
    fn read_only(self) -> Self;
    /// Appends a target covering `length` sectors starting at `start`.
    fn add<T: Target + Display>(self, start: u64, length: u64, target: T) -> io::Result<Self>;
}
