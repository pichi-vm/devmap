// SPDX-License-Identifier: Apache-2.0

//! A high-level Linux device-mapper ioctl layer.
//!
//! This crate lets you create device-mapper devices, load and read back
//! their tables, suspend/resume them, and query their status, all through
//! safe Rust types.
//!
//! [`Control`] is a factory for [`Device`]s: `open`/`create`/`by_device`/
//! `by_node`/`by_name`/`by_uuid`/`list`. Every other operation — loading a
//! table, suspending, resuming, removing, querying status — is a method
//! on `Device` itself. `Device` is a plain, non-destructive handle;
//! [`Removed`] is the auto-removing wrapper `Control::create` returns.
//! Devices are identified by a [`DevId`] (`major:minor`).
//!
//! A table is built with [`Device::builder`], adding [`targets`] one at a
//! time; it is read back with [`Device::table`] (the mapping) or
//! [`Device::info`] (runtime status), each yielding [`Row`]s decoded via
//! [`Row::parse`]. Each target type is a struct implementing [`Target`],
//! so callers can define their own out-of-tree targets.
//!
//! Not covered here: `DM_DEV_RENAME`, `DM_DEV_WAIT`/event polling,
//! `DM_TABLE_DEPS`, and clearing a staged inactive table.
//!
//! # Example
//!
//! Create a device, back it with a single `zero` target, activate it, and
//! let the [`Removed`] guard remove it on drop:
//!
//! ```no_run
//! use devmap::{Control, targets::Zero};
//!
//! # fn main() -> Result<(), devmap::Error> {
//! let control = Control::open()?;               // needs CAP_SYS_ADMIN
//! let dev = control.create("my-zero")?;         // a `Removed` guard
//!
//! // Map 8192 sectors of discard-writes / zero-reads.
//! dev.builder().add(0, 8192, Zero)?.load()?;
//! dev.resume()?;                                // promote the staged table
//!
//! let status = dev.status()?;
//! assert_eq!(status.target_count(), 1);
//! println!("{} has {} target(s)", dev.id(), status.target_count());
//! # Ok(())
//! # }                                            // `dev` drops here -> DM_DEV_REMOVE
//! ```

#![warn(missing_docs)]

mod control;
mod device;
mod error;
mod header;
mod table;
pub mod targets;
mod uapi;

pub use control::Control;
pub use device::{DevId, Device, Removed, Status};
pub use error::Error;
pub use table::{ParseError, RawInfo, Row, TableBuilder, Target, mode};

/// The primary handles are cheap to clone and safe to share across
/// threads; assert it at compile time so a future field addition can't
/// silently regress it.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Control>();
    assert_send_sync::<Device>();
    assert_send_sync::<Removed>();
};
