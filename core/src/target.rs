// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

/// Associates a kernel target name with its table and runtime-status types.
///
/// Implement [`Display`](std::fmt::Display) to encode target arguments without
/// NUL bytes. Row ranges and table access mode belong to the backend, not these
/// arguments.
pub trait Target: Sized {
    /// Nonempty kernel target name, shorter than 16 bytes, without NUL or whitespace.
    const NAME: &'static str;
    /// Parsed construction parameters returned by table read-back.
    ///
    /// The kernel may normalize these from the original input.
    type Table: FromStr;
    /// Parsed runtime status returned by a status query.
    ///
    /// Use [`String`] to retain status text without validation, or
    /// [`Empty`](crate::parse::Empty) when only empty or whitespace-only status is valid.
    type Info: FromStr;
}
