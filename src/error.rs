// SPDX-License-Identifier: Apache-2.0

//! Errors from the device-mapper ioctl layer.

use thiserror::Error;

/// Errors from the device-mapper ioctl layer. Operational failures only —
/// this crate validates nothing chain-related (no superblocks, no salts).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Caller-side misuse (e.g. an overlong or NUL-containing device name)
    /// caught before any ioctl was attempted.
    #[error("usage: {0}")]
    Usage(String),

    /// A `(major, minor)` pair that can't be represented as a device-mapper
    /// `dev_t`: the major exceeds 12 bits or the minor exceeds 20 bits.
    #[error("dev_t out of range: {major}:{minor} (major must fit 12 bits, minor 20 bits)")]
    DevIdRange {
        /// The rejected major number.
        major: u32,
        /// The rejected minor number.
        minor: u32,
    },

    /// A non-ioctl I/O failure (opening `/dev/mapper/control`, `stat()`ing
    /// a device node, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A dm ioctl itself failed. `table_line` is attached only for
    /// `DM_TABLE_LOAD` failures, giving the operator-facing rendering of
    /// the table line that was rejected.
    #[error(
        "dm ioctl {op} failed: {source}{}",
        table_line.as_deref().map(|s| format!(" (table: {s})")).unwrap_or_default()
    )]
    DmIoctl {
        /// The ioctl command name, e.g. `"DM_DEV_CREATE"`.
        op: &'static str,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
        /// Present only for `DM_TABLE_LOAD` failures.
        table_line: Option<String>,
    },

    /// `DM_DEV_CREATE` failed because a device with that name already
    /// exists (`EEXIST`, or `EBUSY` if it exists but is in an
    /// intermediate state).
    #[error("dm device name conflict: /dev/mapper/{name} already exists")]
    NameConflict {
        /// The name that was already taken.
        name: String,
    },
}
