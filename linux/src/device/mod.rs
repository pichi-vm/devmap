// SPDX-License-Identifier: Apache-2.0

//! [`Device`]: a plain, non-destructive handle identified by `dev_t`.
//! [`Status`]: `DM_DEV_STATUS`'s fixed-size fields.

mod guard;
mod status;
pub use guard::Guard;
pub use status::Status;

use std::fmt;
use std::fs::File;
use std::io;
use std::sync::Arc;

use crate::header::DmHeader;
use crate::table::{InfoMode, Mode, Row, TableBuilder, TableMode};
use crate::uapi::{
    DM_DEV_REMOVE, DM_DEV_STATUS, DM_DEV_SUSPEND, DM_DEV_WAIT, DM_IOCTL_VERSION_MAJOR,
    DM_TABLE_CLEAR,
};

use crate::DevId;

/// Decode the kernel's 32-bit `dev_t` stored in its 64-bit ioctl field.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn decode_dev_t(value: u64) -> DevId {
    DevId::from(value as u32)
}

/// Assert the kernel returned the dm-ioctl major version this crate is
/// built against. Every ioctl call site checks this after the ioctl
/// succeeds; centralized here so the error text can't drift between paths.
pub(crate) fn check_version(header: &DmHeader) -> io::Result<()> {
    if header.major_version() != DM_IOCTL_VERSION_MAJOR {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "kernel returned dm-ioctl version major {}; require {}",
                header.major_version(),
                DM_IOCTL_VERSION_MAJOR
            ),
        ));
    }
    Ok(())
}

/// A handle to a device-mapper device, identified purely by its
/// [`DevId`]. Plain and non-destructive: dropping a `Device` does nothing
/// to the underlying kernel object — a dm device outlives the process that
/// created it, and tearing one down is an explicit
/// [`remove`](Device::remove).
///
/// `Clone` is cheap (a `DevId` plus a reference-counted control fd).
/// Equality and hashing are by `DevId` identity only — two handles to the
/// same device compare equal regardless of how each was obtained; the
/// underlying control fd is not part of identity.
#[derive(Clone)]
pub struct Device {
    dev_t: DevId,
    control: Arc<File>,
}

impl PartialEq for Device {
    fn eq(&self, other: &Self) -> bool {
        self.dev_t == other.dev_t
    }
}
impl Eq for Device {}
impl std::hash::Hash for Device {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.dev_t.hash(state);
    }
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `control` is deliberately omitted: a raw fd number adds nothing
        // useful to a Debug rendering.
        f.debug_struct("Device")
            .field("dev_t", &self.dev_t)
            .finish_non_exhaustive()
    }
}

impl Device {
    pub(crate) fn new(dev_t: DevId, control: Arc<File>) -> Self {
        Self { dev_t, control }
    }

    /// This device's `(major, minor)` identity.
    pub fn id(&self) -> DevId {
        self.dev_t
    }

    /// Where this device's block node lives: `/dev/dm-<minor>`. See
    /// the kernel device number for why this and not `/dev/mapper/<name>`.
    /// Constructing the path does not touch the filesystem. Open it with
    /// [`File::open`] or caller-selected [`std::fs::OpenOptions`].
    pub fn node_path(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/dev/dm-{}", self.dev_t.minor()))
    }

    /// Begin building a table to `DM_TABLE_LOAD`. Add targets with
    /// [`TableBuilder::add`] and finish with [`TableBuilder::load`]; the
    /// staged table activates on the next [`Device::resume`].
    ///
    /// ```no_run
    /// # use devmap_linux::Control;
    /// use devmap_linux::target::zero::ZeroTarget;
    /// # fn f(dev: &devmap_linux::device::Device) -> std::io::Result<()> {
    /// dev.builder().add(0, 8192, ZeroTarget)?.load()?;
    /// # Ok(()) }
    /// ```
    #[must_use = "a TableBuilder does nothing until `.load()` is called"]
    pub fn builder(&self) -> TableBuilder {
        TableBuilder::new(Arc::clone(&self.control), self.dev_t)
    }

    fn suspend_or_resume(&self, suspend: bool) -> io::Result<()> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        header.set_suspend(suspend);
        DM_DEV_SUSPEND.ioctl(&*self.control, &mut header)?;
        check_version(&header)
    }

    /// `DM_DEV_SUSPEND` with the suspend flag set: flush in-flight I/O and
    /// queue new I/O until [`Device::resume`] is called.
    pub fn suspend(&self) -> io::Result<()> {
        self.suspend_or_resume(true)
    }

    /// `DM_DEV_SUSPEND` with the suspend flag cleared: unblock queued I/O,
    /// atomically promoting any table staged in the inactive slot.
    pub fn resume(&self) -> io::Result<()> {
        self.suspend_or_resume(false)
    }

    pub(crate) fn remove_now(&self, deferred: bool) -> io::Result<()> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        if deferred {
            header.set_deferred_remove();
        }
        DM_DEV_REMOVE.ioctl(&self.control, &mut header)?;
        check_version(&header)
    }

    /// `DM_DEV_REMOVE`. Remove the device immediately when `deferred` is
    /// `false`. When `true`, set `DM_DEFERRED_REMOVE`: remove it now if unused,
    /// or ask the kernel to remove it when the last holder closes it.
    /// A successful deferred request survives this process exiting.
    ///
    /// Immediate removal fails when the device is still open.
    pub fn remove(self, deferred: bool) -> io::Result<()> {
        self.remove_now(deferred)
    }

    /// `DM_DEV_STATUS` using this device's own `dev_t`.
    pub fn status(&self) -> io::Result<Status> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        DM_DEV_STATUS.ioctl(&*self.control, &mut header)?;
        check_version(&header)?;
        Ok(Status::from_header(&header))
    }

    /// `DM_DEV_WAIT` — block until the device's event counter advances
    /// past `event_nr`, then return the new [`Status`].
    ///
    /// dm devices raise an event on table changes and on target-specific
    /// progress: a snapshot-merge finishing, a raid resync or reshape
    /// completing, a thin-pool crossing its low-water mark. Pass the
    /// `event_nr` from an earlier [`Status`] and this sleeps in the kernel
    /// until something happens, rather than spinning on [`Device::status`].
    ///
    /// Because the wait is against a *previously observed* counter, there
    /// is no lost-wakeup window: an event that fires between the status
    /// read and this call has already advanced the counter, so the ioctl
    /// returns immediately.
    pub fn wait(&self, event_nr: u32) -> io::Result<Status> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        header.set_event_nr(event_nr);
        DM_DEV_WAIT.ioctl(&*self.control, &mut header)?;
        check_version(&header)?;
        Ok(Status::from_header(&header))
    }

    /// `DM_TABLE_CLEAR` — discard the staged inactive table, leaving the
    /// active one untouched.
    ///
    /// Without this the only way to abandon a table that was loaded but
    /// not yet resumed is to activate it or tear the device down.
    ///
    /// Clearing when no inactive table is staged is not an error.
    pub fn clear(&self) -> io::Result<()> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        DM_TABLE_CLEAR.ioctl(&*self.control, &mut header)?;
        check_version(&header)
    }

    /// `DM_TABLE_DEPS` — the block devices the active table depends on.
    ///
    /// One entry per distinct device the table opens, which is what a
    /// caller needs to tear a stack down in the right order, or to check
    /// nothing else is still holding a lower device.
    pub fn deps(&self) -> io::Result<Vec<DevId>> {
        let buf = crate::control::ioctl_with_growing_buffer(
            &self.control,
            |fd, h| crate::uapi::DM_TABLE_DEPS.ioctl(fd, h),
            DmHeader::by_dev(u64::from(self.dev_t)),
            &[],
            4096,
        )?;
        parse_deps(&buf)
    }

    /// `DM_TABLE_STATUS` in table mode (`STATUSTYPE_TABLE`) — the active
    /// table's construction params, one [`Row<TableMode>`] per target.
    /// Reconstruct a target with [`Row::parse`]. Target versions are resolved
    /// before rows are returned.
    pub fn table(&self) -> io::Result<impl Iterator<Item = Row<TableMode>>> {
        let mut header = DmHeader::by_dev(u64::from(self.dev_t));
        header.set_status_table();
        self.table_status_iter(header)
    }

    /// `DM_TABLE_STATUS` in info mode (`STATUSTYPE_INFO`) — per-target
    /// runtime status, one [`Row<InfoMode>`] per target. Decode with
    /// [`Row::parse`]. Target versions are resolved before rows are returned.
    pub fn info(&self) -> io::Result<impl Iterator<Item = Row<InfoMode>>> {
        let header = DmHeader::by_dev(u64::from(self.dev_t));
        self.table_status_iter(header)
    }

    #[allow(clippy::large_types_passed_by_value)] // DmHeader is a cheap Copy value, not "large"
    fn table_status_iter<M: Mode>(
        &self,
        header: DmHeader,
    ) -> io::Result<std::vec::IntoIter<Row<M>>> {
        let buf = crate::control::ioctl_with_growing_buffer(
            &self.control,
            |fd, h| crate::uapi::DM_TABLE_STATUS.ioctl(fd, h),
            header,
            &[],
            4096,
        )?;
        let parsed = DmHeader::response(&buf)?;
        let target_count = parsed.target_count();
        let data_start = (parsed.data_start() as usize).min(buf.len());
        let raw = crate::table::TableStatusIter::<M>::new(buf, data_start, target_count);
        let rows = crate::table::version_rows(raw, |name| {
            crate::control::target_version(&self.control, name).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("query version for target {name:?}: {error}"),
                )
            })
        })?;

        Ok(rows.into_iter())
    }
}

/// Extracts `DM_TABLE_DEPS`' device list from a response buffer. Split
/// out from [`Device::deps`] so the parsing logic is unit-testable
/// against a synthetic buffer, without a real ioctl.
///
/// The payload is a `struct dm_target_deps`: a `u32` count, a `u32` of
/// padding, then that many `u64` `dev_t`s. Every read is bounded by the
/// actual buffer, so a truncated payload yields a short list. A truncated
/// header is an `InvalidData` error.
fn parse_deps(buf: &[u8]) -> io::Result<Vec<DevId>> {
    let parsed = DmHeader::response(buf)?;
    let start = (parsed.data_start() as usize).min(buf.len());
    // The count and its padding word must both be present.
    let Some(first) = start.checked_add(8) else {
        return Ok(Vec::new());
    };
    if first > buf.len() {
        return Ok(Vec::new());
    }
    let count = u32::from_ne_bytes(buf[start..start + 4].try_into().unwrap()) as usize;
    // Trust the count only as far as the buffer actually reaches.
    let available = (buf.len() - first) / 8;
    Ok((0..count.min(available))
        .map(|i| {
            let off = first + i * 8;
            let dev = u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
            decode_dev_t(dev)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    #[test]
    fn dropping_a_device_handle_touches_no_kernel_state() {
        // A `Device` is a handle, not an owner. The control fd here is
        // `/dev/null`, which would reject a `DM_DEV_REMOVE` ioctl — so if a
        // drop guard ever came back and swallowed its error, this test would
        // still pass, and a live-device test would be the one to catch it.
        // What it does pin down is that dropping a handle is infallible and
        // silent: removal is only ever spelled `remove`.
        let device = Device::new(DevId::new(252, 5).unwrap(), dummy_control());
        let id = device.id();
        drop(device);
        assert_eq!(id, DevId::new(252, 5).unwrap());
    }

    #[test]
    fn dev_id_rejects_out_of_range() {
        assert!(DevId::new(0x1000, 0).is_none(), "major over 12 bits");
        assert!(DevId::new(0, 0x10_0000).is_none(), "minor over 20 bits");
        assert!(
            DevId::new(0xfff, 0xf_ffff).is_some(),
            "the maxima are in range"
        );
    }

    #[test]
    fn metadata_rejects_a_non_block_device() {
        // A regular file has a meaningless st_rdev; conversion must refuse it
        // rather than hand back device 0:0.
        let path = std::env::temp_dir().join(format!("devmap-devid-{}", std::process::id()));
        std::fs::write(&path, b"not a block device").expect("seed file");
        let err = DevId::try_from(std::fs::metadata(&path).unwrap())
            .expect_err("regular file must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn dev_id_round_trips() {
        for (major, minor) in [(0u32, 0u32), (252, 5), (7, 0), (0xfff, 0xf_ffff), (1, 1)] {
            let id = DevId::new(major, minor).unwrap();
            assert_eq!(
                decode_dev_t(u64::from(id)),
                id,
                "major={major} minor={minor}"
            );
        }
    }

    #[test]
    fn dev_id_matches_known_bit_layout() {
        // Pin the packing against concrete constants, not just a round trip
        // (which can't catch an encode/decode pair that share the same bug).
        // 252 = 0xfc, minor 5 -> 0xfc05 in the classic packed encoding.
        assert_eq!(u64::from(DevId::new(252, 5).unwrap()), 0xfc05);
        assert_eq!(decode_dev_t(0xfc05), DevId::new(252, 5).unwrap());

        // A minor large enough to spill into the high bits [31:20].
        // major=1 -> [19:8], minor=0x12345 -> low 8 at [7:0], high 12 at [31:20].
        assert_eq!(u64::from(DevId::new(1, 0x1_2345).unwrap()), 0x1230_0145);
        assert_eq!(decode_dev_t(0x1230_0145), DevId::new(1, 0x1_2345).unwrap());
    }

    #[test]
    fn from_dev_t_truncates_high_64_bits() {
        // from_dev_t operates on the low 32 bits only; garbage above bit 31
        // in the kernel-returned u64 must not leak into the result.
        assert_eq!(
            decode_dev_t(0xffff_ffff_0000_fc05),
            DevId::new(252, 5).unwrap()
        );
    }

    #[test]
    fn dev_id_display_uses_kernel_syntax() {
        assert_eq!(DevId::new(252, 5).unwrap().to_string(), "252:5");
        assert_eq!(DevId::new(7, 0).unwrap().to_string(), "7:0");
    }

    /// Hand-builds a synthetic `DM_TABLE_DEPS` response: `data_start`
    /// pointing at a `struct dm_target_deps` (count, padding, then the
    /// `dev_t` array). `claimed_count` is written into the count field
    /// independently of how many devices are actually appended, so the
    /// truncation guard can be exercised.
    #[allow(clippy::cast_possible_truncation)] // test fixture, sizes are tiny
    fn synthetic_deps_response(claimed_count: u32, devs: &[u64]) -> Vec<u8> {
        let total = DmHeader::SIZE + 8 + devs.len() * 8;
        let mut buf = vec![0u8; total];
        buf[16..20].copy_from_slice(&(DmHeader::SIZE as u32).to_ne_bytes());
        buf[12..16].copy_from_slice(&(total as u32).to_ne_bytes());
        buf[DmHeader::SIZE..DmHeader::SIZE + 4].copy_from_slice(&claimed_count.to_ne_bytes());
        for (i, dev) in devs.iter().enumerate() {
            let off = DmHeader::SIZE + 8 + i * 8;
            buf[off..off + 8].copy_from_slice(&dev.to_ne_bytes());
        }
        buf
    }

    #[test]
    fn parse_deps_reads_the_device_array() {
        let devs = [
            u64::from(DevId::new(7, 0).unwrap()),
            u64::from(DevId::new(252, 5).unwrap()),
        ];
        let buf = synthetic_deps_response(2, &devs);
        assert_eq!(
            parse_deps(&buf).unwrap(),
            [DevId::new(7, 0).unwrap(), DevId::new(252, 5).unwrap()]
        );
    }

    #[test]
    fn parse_deps_yields_nothing_for_an_empty_list() {
        assert_eq!(parse_deps(&synthetic_deps_response(0, &[])).unwrap(), []);
    }

    #[test]
    fn parse_deps_rejects_a_short_header() {
        assert_eq!(
            parse_deps(&[]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn parse_deps_clamps_a_count_past_the_buffer_end() {
        // The kernel claims 100 devices but only one is present: reading
        // all 100 would slice out of bounds.
        let buf = synthetic_deps_response(100, &[u64::from(DevId::new(7, 0).unwrap())]);
        assert_eq!(parse_deps(&buf).unwrap(), [DevId::new(7, 0).unwrap()]);
    }

    #[test]
    fn parse_deps_handles_a_response_with_no_room_for_the_count() {
        // data_start at the very end of the buffer: not even the count and
        // its padding word fit.
        let mut buf = vec![0u8; DmHeader::SIZE];
        #[allow(clippy::cast_possible_truncation)]
        buf[16..20].copy_from_slice(&(DmHeader::SIZE as u32).to_ne_bytes());
        assert_eq!(parse_deps(&buf).unwrap(), []);
    }
}
