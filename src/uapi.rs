// SPDX-License-Identifier: Apache-2.0

//! Kernel UAPI mirrors + iocuddle ioctl-number declarations. This is the
//! ONLY module in the crate that needs `#![allow(unsafe_code)]` — every
//! unsafe block here is an iocuddle const constructor.
//!
//! Raw structs (`dm_ioctl_raw`, `dm_target_spec_raw`) are `pub(crate)` so
//! the safe wrappers in [`super::header`]/[`super::table`] can use them,
//! but they never cross the crate boundary. All field layouts and command
//! numbers below were verified against `/usr/include/linux/dm-ioctl.h`
//! directly, not from memory.

#![allow(unsafe_code)]

use iocuddle::{Group, Ioctl, WriteRead};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub(crate) const DM_NAME_LEN: usize = 128;
pub(crate) const DM_UUID_LEN: usize = 129;
pub(crate) const DM_MAX_TYPE_NAME: usize = 16;

pub(crate) const DM_IOCTL_VERSION_MAJOR: u32 = 4;

/// Mirror of `struct dm_ioctl` from `<linux/dm-ioctl.h>`. Field order is
/// byte-for-byte identical to the kernel UAPI. Sizeof locked at 312 bytes
/// by a unit test in [`super::header`].
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(crate) struct dm_ioctl_raw {
    pub version: [u32; 3],
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; DM_NAME_LEN],
    pub uuid: [u8; DM_UUID_LEN],
    pub data: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<dm_ioctl_raw>() == 312);

/// Mirror of `struct dm_target_spec`. Sizeof locked at 40 bytes.
///
/// `next`'s meaning depends on direction: for `DM_TABLE_LOAD` (writing)
/// it's the byte offset from *this* spec's start to the next one; for
/// `DM_TABLE_STATUS` (reading) it's the byte offset from the *first*
/// spec's start to the next one. See `<linux/dm-ioctl.h>`'s comment on
/// `struct dm_target_spec` — this asymmetry is easy to miss and easy to
/// get wrong.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[allow(non_camel_case_types)]
pub(crate) struct dm_target_spec_raw {
    pub sector_start: u64,
    pub length: u64,
    pub status: i32,
    pub next: u32,
    pub target_type: [u8; DM_MAX_TYPE_NAME],
}

const _: () = assert!(core::mem::size_of::<dm_target_spec_raw>() == 40);

pub(crate) const DM_TARGET_SPEC_SIZE: usize = core::mem::size_of::<dm_target_spec_raw>();

/// `DM_READONLY_FLAG` — the device is (or should be) read-only.
pub(crate) const DM_READONLY_FLAG: u32 = 1 << 0;

/// `DM_SUSPEND_FLAG` — set to suspend, clear to resume.
pub(crate) const DM_SUSPEND_FLAG: u32 = 1 << 1;

/// `DM_ACTIVE_PRESENT_FLAG` — an active table is present (response-only).
pub(crate) const DM_ACTIVE_PRESENT_FLAG: u32 = 1 << 5;

/// `DM_INACTIVE_PRESENT_FLAG` — an inactive (staged) table is present
/// (response-only).
pub(crate) const DM_INACTIVE_PRESENT_FLAG: u32 = 1 << 6;

/// `DM_UEVENT_GENERATED_FLAG` — a uevent was generated for the last
/// operation (response-only).
pub(crate) const DM_UEVENT_GENERATED_FLAG: u32 = 1 << 13;

/// Set in the response when the caller's buffer was too small for
/// `DM_LIST_DEVICES`/`DM_TABLE_STATUS`'s variable-length output.
pub(crate) const DM_BUFFER_FULL_FLAG: u32 = 1 << 8;

/// Set in the response when `DM_TARGET_MSG` wrote a reply string into the
/// data area (not every message produces one).
pub(crate) const DM_DATA_OUT_FLAG: u32 = 1 << 16;

const DM_IOCTL_GROUP: Group = Group::new(0xfd);

// SAFETY: every dm ioctl is `_IOWR(0xfd, N, struct dm_ioctl)` per
// `<linux/dm-ioctl.h>` — confirmed directly against the installed header,
// not from memory. We declare against `&super::header::DmHeader`, a
// `#[repr(transparent)]` newtype over `dm_ioctl_raw` with private fields
// and invariant-enforcing constructors, satisfying iocuddle's
// "T provides safe wrappers around its raw contents" contract.
pub(crate) const DM_DEV_CREATE: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(3) };
pub(crate) const DM_DEV_REMOVE: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(4) };
pub(crate) const DM_DEV_SUSPEND: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(6) };
pub(crate) const DM_DEV_STATUS: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(7) };
pub(crate) const DM_TABLE_LOAD: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(9) };
pub(crate) const DM_LIST_DEVICES: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(2) };
pub(crate) const DM_TABLE_STATUS: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(12) };
pub(crate) const DM_TARGET_MSG: Ioctl<WriteRead, &super::header::DmHeader> =
    unsafe { DM_IOCTL_GROUP.write_read(14) };
