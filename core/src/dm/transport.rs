// SPDX-License-Identifier: Apache-2.0

use super::Target;
use std::{fmt::Display, io};

/// Creates devices for format workflows that need a temporary kernel table.
///
/// Lets a format crate perform kernel-assisted initialization without
/// depending on a concrete backend. The caller supplies the backend and name.
///
/// Implementations must not remove devices implicitly when handles are dropped.
pub trait Control {
    /// The backend's device handle.
    type Device: Device;
    /// Creates an empty named device without replacing an existing device.
    fn create(&self, name: &str) -> io::Result<Self::Device>;
}

/// Device operations needed by kernel-assisted format workflows.
///
/// A format workflow uses this handle to prepare a table, activate it, and
/// explicitly clean up its temporary mapping. It controls a mapping, not the
/// bytes stored on the mapped device.
pub trait Device: Sized {
    /// The backend's inactive-table builder.
    type TableBuilder: TableBuilder;
    /// Starts an empty inactive table.
    fn builder(&self) -> Self::TableBuilder;
    /// Promotes the inactive table and resumes I/O.
    fn resume(&self) -> io::Result<()>;
    /// Explicitly removes the device, failing if it is busy.
    fn remove(self) -> io::Result<()>;
    /// Requests removal once remaining holders release the device.
    fn remove_deferred(self) -> io::Result<()>;
}

/// Builds an inactive table with explicit row lengths and access mode.
///
/// Lets format code add correctly sized rows and request read-only access
/// without encoding backend-specific table buffers. Loading the table and
/// activating it with [`Device::resume`] are separate operations.
pub trait TableBuilder: Sized {
    /// Sets read-only access for the whole table.
    #[must_use]
    fn read_only(self) -> Self;
    /// Appends a target covering `length` sectors starting at `start`.
    fn add<T: Target + Display>(self, start: u64, length: u64, target: T) -> io::Result<Self>;
    /// Loads the table without resuming the device.
    fn load(self) -> io::Result<()>;
}

/// Sends commands to one already-selected target in a live device.
///
/// Format crates provide command methods on endpoints whose [`Target`](Self::Target)
/// matches their target type. The backend owns device and sector selection;
/// the format crate owns command syntax and reply parsing.
pub trait TargetEndpoint {
    /// The target kind selected by this endpoint.
    type Target: Target;
    /// Sends a command and returns any textual reply.
    ///
    /// Kernel and transport errors are retained. Success may change device
    /// state; absence of a reply is not a failure.
    fn message(&self, command: &str) -> io::Result<Option<String>>;
}
