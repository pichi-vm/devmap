// SPDX-License-Identifier: Apache-2.0

//! A high-level, `iocuddle`-based Linux device-mapper ioctl layer.
//!
//! Every dm ioctl this crate issues is `_IOWR` over `struct dm_ioctl` —
//! confirmed directly against `<linux/dm-ioctl.h>`, not from memory (see
//! the crate-private `uapi` module). None of the kernel structs involved (`dm_ioctl`,
//! `dm_target_spec`, `dm_name_list`) embed a pointer field, so this crate
//! needs none of `iocuddle`'s `Ptr`/`PtrMut` machinery — every argument
//! type here is a plain `FromBytes + IntoBytes + Immutable + KnownLayout`
//! struct, satisfying iocuddle's "Requirements on T" contract by
//! representation alone.
//!
//! [`Control`] is a factory for [`Device`]s: `open`/`create`/`by_device`/
//! `by_node`/`by_name`/`by_uuid`/`list`. Every other operation — loading a
//! table, suspending, resuming, removing, querying status — is a method
//! on `Device` itself. `Device` is a plain, non-destructive handle;
//! [`Removed`] is the auto-removing wrapper `Control::create` returns.
//! Devices are identified by a [`DevId`] (`major:minor`), and a table is a
//! slice of [`TableLine`]s, each pairing a sector range with a [`Target`].
//!
//! Not covered here (deliberately, for now): `DM_DEV_RENAME`,
//! `DM_DEV_WAIT`/event polling, `DM_TABLE_DEPS`, and clearing a staged
//! inactive table.
//!
//! # Example
//!
//! Create a device, back it with a single `zero` target, activate it, and
//! let the [`Removed`] guard remove it on drop:
//!
//! ```no_run
//! use devmap::{Control, Target, TableLine};
//!
//! # fn main() -> Result<(), devmap::Error> {
//! let control = Control::open()?;               // needs CAP_SYS_ADMIN
//! let dev = control.create("my-zero")?;         // a `Removed` guard
//!
//! // Map 8192 sectors of discard-writes / zero-reads.
//! dev.load_table(&[TableLine::new(0, 8192, Target::Zero)])?;
//! dev.resume()?;                                // promote the staged table
//!
//! let status = dev.status()?;
//! assert_eq!(status.target_count(), 1);
//! println!("{} has {} target(s)", dev.id(), status.target_count());
//! # Ok(())
//! # }                                            // `dev` drops here -> DM_DEV_REMOVE
//! ```

mod control;
mod device;
mod error;
mod header;
mod table;
mod uapi;

pub use control::Control;
pub use device::{DevId, Device, Removed, Status};
pub use error::Error;
pub use table::{
    DelayLeg, FlakeyDirection, FlakeyFeature, IntegrityBuilder, IntegrityMode, RaidDevicePair, RaidType,
    TableLine, Target, ThinPoolBuilder, WritecacheBuilder, WritecacheKind,
};

/// The primary handles are cheap to clone and safe to share across
/// threads; assert it at compile time so a future field addition can't
/// silently regress it.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Control>();
    assert_send_sync::<Device>();
    assert_send_sync::<Removed>();
};
