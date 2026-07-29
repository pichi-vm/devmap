// SPDX-License-Identifier: Apache-2.0

//! [`DmHeader`]: safe `#[repr(transparent)]` newtype over `dm_ioctl_raw`.
//!
//! This is the type iocuddle's typed ioctl declarations reference. Fields
//! are private; every mutator enforces the kernel's coherency invariants
//! (NUL-terminated name/uuid within their length limits, `version =
//! [4, 0, 0]`, `data_size`/`data_start` correct for a fixed-size exchange
//! by default). Supports building a header keyed by name, uuid, or raw
//! `dev` — mutually exclusive, matching the kernel's own lookup priority
//! (name, then uuid, then dev).

use crate::Error;
use crate::uapi::{DM_IOCTL_VERSION_MAJOR, DM_NAME_LEN, DM_UUID_LEN, DM_SUSPEND_FLAG, dm_ioctl_raw};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Safe wrapper over `dm_ioctl`. Hides the UAPI; only construction +
/// flagged accessors are exposed. `#[repr(transparent)]` guarantees
/// identical layout to `dm_ioctl_raw`, required so iocuddle can pass
/// `&mut DmHeader` as the ioctl argument.
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub(crate) struct DmHeader {
    inner: dm_ioctl_raw,
}

impl DmHeader {
    pub(crate) const SIZE: usize = core::mem::size_of::<dm_ioctl_raw>();

    /// A header with no identification set at all — used for ioctls like
    /// `DM_LIST_DEVICES` that ignore name/uuid/dev and always operate on
    /// every device.
    pub(crate) fn any() -> Self {
        Self::blank()
    }

    // `DmHeader::SIZE` is a fixed 312-byte constant, nowhere near u32::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn blank() -> Self {
        Self {
            inner: dm_ioctl_raw {
                version: [DM_IOCTL_VERSION_MAJOR, 0, 0],
                data_size: Self::SIZE as u32,
                data_start: Self::SIZE as u32,
                target_count: 0,
                open_count: 0,
                flags: 0,
                event_nr: 0,
                padding: 0,
                dev: 0,
                name: [0; DM_NAME_LEN],
                uuid: [0; DM_UUID_LEN],
                data: [0; 7],
            },
        }
    }

    /// A header identifying a device by name (used both for `DM_DEV_CREATE`
    /// and for looking up an existing device).
    pub(crate) fn by_name(name: &str) -> Result<Self, Error> {
        let mut header = Self::blank();
        let bytes = name.as_bytes();
        if bytes.len() >= DM_NAME_LEN {
            return Err(Error::Usage(format!(
                "dm device name too long: {} bytes (max {})",
                bytes.len(),
                DM_NAME_LEN - 1
            )));
        }
        if bytes.contains(&0) {
            return Err(Error::Usage("dm device name contains NUL byte".into()));
        }
        header.inner.name[..bytes.len()].copy_from_slice(bytes);
        Ok(header)
    }

    /// A header identifying a device by uuid.
    pub(crate) fn by_uuid(uuid: &str) -> Result<Self, Error> {
        let mut header = Self::blank();
        let bytes = uuid.as_bytes();
        if bytes.len() >= DM_UUID_LEN {
            return Err(Error::Usage(format!(
                "dm uuid too long: {} bytes (max {})",
                bytes.len(),
                DM_UUID_LEN - 1
            )));
        }
        if bytes.contains(&0) {
            return Err(Error::Usage("dm uuid contains NUL byte".into()));
        }
        header.inner.uuid[..bytes.len()].copy_from_slice(bytes);
        Ok(header)
    }

    /// A header identifying a device by its raw `dev_t` — the kernel's
    /// lookup falls back to this when both `name` and `uuid` are empty.
    pub(crate) fn by_dev(dev_t: u64) -> Self {
        let mut header = Self::blank();
        header.inner.dev = dev_t;
        header
    }

    /// Toggle `DM_SUSPEND_FLAG` in place — set to suspend, clear to resume.
    pub(crate) fn set_suspend(&mut self, suspend: bool) {
        if suspend {
            self.inner.flags |= DM_SUSPEND_FLAG;
        } else {
            self.inner.flags &= !DM_SUSPEND_FLAG;
        }
    }

    /// Set total buffer size (for variable-length `DM_TABLE_LOAD`,
    /// `DM_LIST_DEVICES`, `DM_TABLE_STATUS`).
    pub(crate) fn set_data_size(&mut self, size: u32) {
        self.inner.data_size = size;
    }

    pub(crate) fn set_target_count(&mut self, count: u32) {
        self.inner.target_count = count;
    }

    /// Test-only: overwrite the raw `flags` word, simulating what the kernel
    /// writes back (e.g. `DM_BUFFER_FULL_FLAG`). Not part of the normal API —
    /// production code never sets arbitrary flags.
    #[cfg(test)]
    pub(crate) fn set_flags_raw(&mut self, flags: u32) {
        self.inner.flags = flags;
    }

    /// Test-only: overwrite the major version the kernel is pretending to
    /// have returned, to exercise the version-mismatch path.
    #[cfg(test)]
    pub(crate) fn set_major_version(&mut self, major: u32) {
        self.inner.version[0] = major;
    }

    /// Kernel-returned `dev_t` — populated synchronously by `DM_DEV_CREATE`
    /// and returned by any lookup ioctl.
    pub(crate) fn dev(&self) -> u64 {
        self.inner.dev
    }

    /// Kernel-returned dm-ioctl major version. Every call site should
    /// check this == `DM_IOCTL_VERSION_MAJOR` after an ioctl succeeds.
    pub(crate) fn major_version(&self) -> u32 {
        self.inner.version[0]
    }

    pub(crate) fn open_count(&self) -> i32 {
        self.inner.open_count
    }

    pub(crate) fn target_count(&self) -> u32 {
        self.inner.target_count
    }

    pub(crate) fn event_nr(&self) -> u32 {
        self.inner.event_nr
    }

    pub(crate) fn flags(&self) -> u32 {
        self.inner.flags
    }

    pub(crate) fn data_start(&self) -> u32 {
        self.inner.data_start
    }

    pub(crate) fn data_size(&self) -> u32 {
        self.inner.data_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizeof_dm_ioctl_raw() {
        assert_eq!(core::mem::size_of::<dm_ioctl_raw>(), 312);
    }

    #[test]
    fn dmheader_is_layout_identical_to_raw() {
        assert_eq!(core::mem::size_of::<DmHeader>(), core::mem::size_of::<dm_ioctl_raw>());
        assert_eq!(core::mem::align_of::<DmHeader>(), core::mem::align_of::<dm_ioctl_raw>());
    }

    #[test]
    fn by_name_zero_pads_and_sets_version() {
        let h = DmHeader::by_name("foo").unwrap();
        assert_eq!(&h.inner.name[..3], b"foo");
        assert!(h.inner.name[3..].iter().all(|&b| b == 0));
        assert_eq!(h.inner.version, [DM_IOCTL_VERSION_MAJOR, 0, 0]);
        assert_eq!(h.inner.dev, 0);
        assert!(h.inner.uuid.iter().all(|&b| b == 0));
    }

    #[test]
    fn by_name_rejects_nul_and_overlong() {
        assert!(matches!(DmHeader::by_name("foo\0bar"), Err(Error::Usage(_))));
        let long = "a".repeat(200);
        assert!(matches!(DmHeader::by_name(&long), Err(Error::Usage(_))));
    }

    #[test]
    fn by_uuid_sets_uuid_not_name() {
        let h = DmHeader::by_uuid("some-uuid").unwrap();
        assert_eq!(&h.inner.uuid[.."some-uuid".len()], b"some-uuid");
        assert!(h.inner.name.iter().all(|&b| b == 0));
    }

    #[test]
    fn by_dev_sets_dev_not_name_or_uuid() {
        let h = DmHeader::by_dev(0x1234_5678);
        assert_eq!(h.inner.dev, 0x1234_5678);
        assert!(h.inner.name.iter().all(|&b| b == 0));
        assert!(h.inner.uuid.iter().all(|&b| b == 0));
    }

    #[test]
    fn set_suspend_toggles_only_that_bit() {
        let mut h = DmHeader::by_name("x").unwrap();
        h.set_suspend(true);
        assert_eq!(h.flags() & DM_SUSPEND_FLAG, DM_SUSPEND_FLAG);
        h.set_suspend(false);
        assert_eq!(h.flags() & DM_SUSPEND_FLAG, 0);
    }
}
