// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

/// Describes a kernel device-mapper target's table and status grammars.
///
/// A backend uses [`NAME`](Self::NAME) to identify the target and selects
/// [`Table`](Self::Table) or [`Info`](Self::Info) to parse its reply. Keeping
/// these associations on the target lets the backend accept targets from
/// other crates without knowing each format's parameter syntax.
///
/// Implement `Display` to encode target-specific arguments without NUL.
/// Row start/length and whole-table access mode are not target arguments.
/// The kernel may normalize parameters when reporting a loaded table.
pub trait Target: Sized {
    /// Nonempty kernel target name, shorter than 16 bytes, without NUL or whitespace.
    const NAME: &'static str;
    /// Parsed construction parameters returned by table read-back.
    type Table: FromStr;
    /// Parsed runtime status returned by a status query.
    ///
    /// Use [`String`] to retain status text without validation, or
    /// [`NoInfo`](crate::NoInfo) when only empty or whitespace-only status is valid.
    type Info: FromStr;
}
