// SPDX-License-Identifier: Apache-2.0

//! Linux device-mapper control through safe Rust types.
//!
//! Create devices, load tables, suspend or resume I/O, read status, and send
//! target messages. Target definitions and on-disk formats belong to separate
//! crates; import shared interfaces and device numbers from [`devmap_core`].
//! This crate requires Linux and access to `/dev/mapper/control`, normally with
//! `CAP_SYS_ADMIN`.
//!
//! # Creating a mapping
//!
//! Create a device, back it with a single `zero` target, activate it, then
//! remove it:
//!
//! ```no_run
//! use devmap_linux::Control;
//! use devmap_zero::ZeroTarget;
//!
//! # fn main() -> std::io::Result<()> {
//! let control = Control::open()?;
//! let dev = control.create("my-zero")?;
//!
//! // Table ranges are always in 512-byte sectors.
//! dev.builder().add(0, 8192, ZeroTarget)?.load()?;
//! dev.resume()?;
//!
//! let status = dev.status()?;
//! assert_eq!(status.target_count(), 1);
//! println!("{} has {} target(s)", dev.id(), status.target_count());
//!
//! dev.remove()?;
//! # Ok(())
//! # }
//! ```
//!
//! Depend on the target crate used in an example as well as `devmap-linux`.
//! [`TableBuilder::add`] accepts any type implementing
//! [`devmap_core::Target`] and [`std::fmt::Display`];
//! [`TableBuilder::add_raw`] accepts kernel table text.
//!
//! # Table loading and device lifetime
//!
//! Row start and length use 512-byte sectors regardless of a target's block
//! size. Access mode applies to the whole table. Loading stages an inactive
//! table; [`Device::resume`] promotes it and resumes I/O. Creating, loading,
//! and resuming are separate operations, not an atomic transaction.
//!
//! [`Device`] is a cheap, cloneable handle to persistent kernel state. Dropping
//! it does not remove a device, including after a failed load or resume. Callers
//! must arrange cleanup on error. [`Device::remove`] requests immediate removal
//! and reports `EBUSY` if the device is open. [`Device::remove_deferred`] asks
//! the kernel to remove it when its last holder closes, even if this process
//! has already exited.
//!
//! # Activating an existing verity hash device
//!
//! `devmap-verity` can read a header and construct a target with
//! `default-features = false`; no hashing libraries are needed for this workflow.
//! The root digest must come from an independently trusted source, not the
//! header. Supply its decoded bytes as `trusted_root`:
//!
//! ```no_run
//! use std::fs::File;
//! use devmap_core::parse::DevId;
//! use devmap_linux::Control;
//! use devmap_verity::{Hashes, dm, traits::std::OpenHashes as _};
//!
//! # fn activate(trusted_root: &[u8]) -> std::io::Result<devmap_linux::Device> {
//! let hash_path = "/dev/loop1";
//! let hashes = Hashes::open(File::open(hash_path)?)?;
//! let target = dm::Builder::from(hashes.header()).build(
//!     DevId::from_path("/dev/loop0")?,
//!     DevId::from_path(hash_path)?,
//!     trusted_root,
//! )?;
//!
//! let control = Control::open()?;
//! let device = control.create("verified-data")?;
//! device.builder()
//!     .read_only()
//!     .add(0, target.data_sectors(), target)?
//!     .load()?;
//! device.resume()?;
//! # Ok(device)
//! # }
//! ```
//!
//! This example assumes the header starts at byte zero of the hash device.
//! For an embedded header, read through a zero-based storage region and pass
//! its physical byte offset to the target builder's `header_offset_bytes`.
//! Header validation does not authenticate data or check actual device capacity;
//! the kernel checks the mapping on load and verifies data on reads. Newly
//! formatted storage must be persisted before it is handed to the kernel.
//!
//! # Reading tables, status, and sending commands
//!
//! [`Device::status`] reports whole-device state. [`Device::table`] returns
//! construction parameters and [`Device::info`] returns per-target runtime
//! status. Both yield [`Row`] values, whose [`Row::parse`] method selects
//! [`Target::Table`](devmap_core::Target::Table) or
//! [`Target::Info`](devmap_core::Target::Info) according to the row's mode.
//! Kernels can normalize table parameters; read-back need not equal the
//! original target value. [`Row::params`] always exposes the raw text.
//!
//! [`Device::target`] selects a [`LiveTarget`]. Its [`LiveTarget::info`] method
//! reads typed runtime status. [`Device::message`] sends raw target messages
//! to a selected sector and returns any textual reply.
//!
//! [`Device::wait_event`] blocks for one device's event. [`Control::arm_poll`]
//! arms the control fd for subsystem events; use [`AsFd`](std::os::fd::AsFd)
//! with a `poll`/`epoll` reactor. This is independent of Cargo features.
//!
//! # Cargo features
//!
//! There are no optional features. Target crates are separate dependencies.
//! `DM_DEV_SET_GEOMETRY` and `DM_REMOVE_ALL` are not exposed.

#![warn(missing_docs)]

mod control;
mod device;
mod header;
mod table;
mod uapi;

pub use control::{Control, TargetVersion};
pub use device::{Device, LiveTarget, Status};
pub use table::{Row, TableBuilder, mode};

/// The primary handles are cheap to clone and safe to share across
/// threads; assert it at compile time so a future field addition can't
/// silently regress it.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Control>();
    assert_send_sync::<Device>();
};
