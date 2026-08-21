// SPDX-License-Identifier: Apache-2.0

//! Reaching the kernel's device-mapper control node.
//!
//! Every persona that touches a live mapping starts the same way: open
//! `/dev/mapper/control`, then find the mapping by the name the user typed.
//! Spelled out at each call site that was two error contexts to get right
//! every time, so it is written here once.
//!
//! Each function opens the control node for itself rather than taking one.
//! A [`Device`] holds its own reference to the control fd, so it stays
//! usable after the [`Control`] it came from is dropped, and one process
//! run only ever services a single subcommand — so nothing is gained by
//! threading a handle down through the personas. Opening where the node is
//! actually needed also keeps the subcommands that never touch the kernel
//! —  `verity format`, `crypt dump`, `zoned check` — working without root.

use anyhow::{Context as _, Result};
use devmap_linux::{Control, Device, Status};

/// Open the device-mapper control node.
///
/// For callers that drive the subsystem itself rather than one mapping:
/// creating a device, listing devices, renaming, querying target versions.
///
/// # Errors
///
/// If the node can't be opened — typically for want of `CAP_SYS_ADMIN`.
pub(crate) fn open() -> Result<Control> {
    Control::open().context("open /dev/mapper/control")
}

/// The mapping named `name`, together with its status.
///
/// # Errors
///
/// If the control node can't be opened or no mapping goes by that name.
pub(crate) fn lookup(name: &str) -> Result<(Device, Status)> {
    open()?
        .by_name(name)
        .with_context(|| format!("look up {name}"))
}

/// The mapping named `name`, for callers with no use for its status.
///
/// # Errors
///
/// As [`lookup`].
pub(crate) fn by_name(name: &str) -> Result<Device> {
    Ok(lookup(name)?.0)
}

/// Tear down the mapping named `name`.
///
/// The teardown every persona's `close` verb performs, differing only in
/// which argument type carries the name.
///
/// # Errors
///
/// As [`lookup`], or if the device is still held open by something.
pub(crate) fn remove(name: &str) -> Result<()> {
    by_name(name)?.remove().context("remove")
}
