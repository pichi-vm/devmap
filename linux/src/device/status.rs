// SPDX-License-Identifier: Apache-2.0

use crate::header::DmHeader;

/// Fixed-size fields returned by `DM_DEV_STATUS`.
///
/// Obtained from [`super::Device::status`], [`crate::Control::by_name`], or
/// [`crate::Control::by_uuid`]. The `flags` field retains bits this crate
/// does not yet name; test named bits with the associated masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Status {
    /// Number of open references to the device. Signed to match the kernel.
    pub open_count: i32,
    /// Number of targets in the active table.
    pub target_count: u32,
    /// The device's current event number (see `DM_DEV_WAIT`).
    pub event_nr: u32,
    /// Raw `dm_ioctl.flags` word, including any unknown bits.
    pub flags: u32,
}

impl Status {
    /// The device is read-only.
    pub const READ_ONLY: u32 = 1 << 0;
    /// The device is suspended.
    pub const SUSPENDED: u32 = 1 << 1;
    /// An active table is present.
    pub const ACTIVE_TABLE: u32 = 1 << 5;
    /// An inactive (staged) table is present.
    pub const INACTIVE_TABLE: u32 = 1 << 6;
    /// A uevent was generated for the last operation.
    pub const UEVENT_GENERATED: u32 = 1 << 13;

    pub(crate) fn from_header(header: &DmHeader) -> Self {
        Self {
            open_count: header.open_count(),
            target_count: header.target_count(),
            event_nr: header.event_nr(),
            flags: header.flags(),
        }
    }
}
