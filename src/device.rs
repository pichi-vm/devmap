// SPDX-License-Identifier: Apache-2.0

//! [`Device`]: a plain, non-destructive handle identified by `dev_t`.
//! [`Removed`]: the auto-removing wrapper `Control::create` returns.
//! [`Status`]: `DM_DEV_STATUS`'s fixed-size fields.

use std::fmt;
use std::fs::File;
use std::sync::Arc;

use crate::Error;
use crate::header::DmHeader;
use crate::table::{Row, TableBuilder, mode};
use crate::uapi::{
    DM_ACTIVE_PRESENT_FLAG, DM_DEV_REMOVE, DM_DEV_STATUS, DM_DEV_SUSPEND, DM_INACTIVE_PRESENT_FLAG,
    DM_IOCTL_VERSION_MAJOR, DM_READONLY_FLAG, DM_SUSPEND_FLAG, DM_UEVENT_GENERATED_FLAG,
};

/// A device-mapper device's `(major, minor)` identity — a block device
/// number (`dev_t`). Constructible from a `(u32, u32)` tuple via `From`,
/// and renders as the kernel's `major:minor` syntax via [`fmt::Display`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DevId {
    major: u32,
    minor: u32,
}

impl DevId {
    /// A `DevId` from an explicit major/minor pair.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// The major number.
    pub const fn major(self) -> u32 {
        self.major
    }

    /// The minor number.
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Decode a Linux `dev_t` into `(major, minor)`, matching the classic
    /// 32-bit packed encoding device-mapper uses (and glibc's
    /// `gnu_dev_major`/`gnu_dev_minor` within that range): `dev` bits
    /// `[7:0]` = minor low 8 bits, `[19:8]` = major (12 bits), `[31:20]` =
    /// minor high 12 bits. Only the low 32 bits are consulted.
    #[allow(clippy::cast_possible_truncation)] // intentional: the classic 32-bit dev_t encoding
    pub(crate) fn from_dev_t(dev: u64) -> Self {
        let dev = dev as u32;
        let major = (dev >> 8) & 0xfff;
        let minor = (dev & 0xff) | ((dev >> 12) & 0x000f_ff00);
        Self { major, minor }
    }

    /// Inverse of [`DevId::from_dev_t`].
    pub(crate) fn to_dev_t(self) -> u64 {
        let dev = (self.minor & 0xff) | ((self.major & 0xfff) << 8) | (((self.minor >> 8) & 0xfff) << 20);
        u64::from(dev)
    }
}

impl fmt::Display for DevId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

impl From<(u32, u32)> for DevId {
    /// `(major, minor)`.
    fn from((major, minor): (u32, u32)) -> Self {
        Self { major, minor }
    }
}

/// Assert the kernel returned the dm-ioctl major version this crate is
/// built against. Every ioctl call site checks this after the ioctl
/// succeeds; centralized here so the error text can't drift between paths.
pub(crate) fn check_version(op: &'static str, header: &DmHeader) -> Result<(), Error> {
    if header.major_version() != DM_IOCTL_VERSION_MAJOR {
        return Err(Error::DmIoctl {
            op,
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "kernel returned dm-ioctl version major {}; require {}",
                    header.major_version(),
                    DM_IOCTL_VERSION_MAJOR
                ),
            ),
            table_line: None,
        });
    }
    Ok(())
}

/// A handle to a device-mapper device, identified purely by its
/// [`DevId`]. Plain and non-destructive: dropping a `Device` does nothing
/// to the underlying kernel object. Use [`Removed`] (via `.into()`) to opt
/// in to removal on drop.
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
        f.debug_struct("Device").field("dev_t", &self.dev_t).finish_non_exhaustive()
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

    /// Begin building a table to `DM_TABLE_LOAD`. Add targets with
    /// [`TableBuilder::add`] and finish with [`TableBuilder::load`]; the
    /// staged table activates on the next [`Device::resume`].
    ///
    /// ```no_run
    /// # use devmap::{Control, targets::Zero};
    /// # fn f(dev: &devmap::Device) -> Result<(), devmap::Error> {
    /// dev.builder().add(0, 8192, Zero)?.load()?;
    /// # Ok(()) }
    /// ```
    #[must_use = "a TableBuilder does nothing until `.load()` is called"]
    pub fn builder(&self) -> TableBuilder {
        TableBuilder::new(Arc::clone(&self.control), self.dev_t)
    }

    fn suspend_or_resume(&self, suspend: bool) -> Result<(), Error> {
        let mut header = DmHeader::by_dev(self.dev_t.to_dev_t());
        header.set_suspend(suspend);
        DM_DEV_SUSPEND.ioctl(&*self.control, &mut header).map_err(|source| Error::DmIoctl {
            op: "DM_DEV_SUSPEND",
            source,
            table_line: None,
        })?;
        check_version("DM_DEV_SUSPEND", &header)
    }

    /// `DM_DEV_SUSPEND` with the suspend flag set: flush in-flight I/O and
    /// queue new I/O until [`Device::resume`] is called.
    ///
    /// # Errors
    ///
    /// [`Error::DmIoctl`] if the kernel rejects the suspend.
    pub fn suspend(&self) -> Result<(), Error> {
        self.suspend_or_resume(true)
    }

    /// `DM_DEV_SUSPEND` with the suspend flag cleared: unblock queued I/O,
    /// atomically promoting any table staged in the inactive slot.
    ///
    /// # Errors
    ///
    /// [`Error::DmIoctl`] if the kernel rejects the resume (e.g. a staged
    /// table it can't activate).
    pub fn resume(&self) -> Result<(), Error> {
        self.suspend_or_resume(false)
    }

    fn remove_now(control: &File, dev_t: DevId) -> Result<(), Error> {
        let mut header = DmHeader::by_dev(dev_t.to_dev_t());
        DM_DEV_REMOVE.ioctl(control, &mut header).map_err(|source| Error::DmIoctl {
            op: "DM_DEV_REMOVE",
            source,
            table_line: None,
        })?;
        check_version("DM_DEV_REMOVE", &header)
    }

    /// `DM_DEV_REMOVE`. Explicit, observable-error removal.
    ///
    /// # Errors
    ///
    /// [`Error::DmIoctl`] if the kernel rejects the removal (e.g. the
    /// device is still open).
    pub fn remove(self) -> Result<(), Error> {
        Self::remove_now(&self.control, self.dev_t)
    }

    /// `DM_DEV_STATUS` using this device's own `dev_t`.
    ///
    /// # Errors
    ///
    /// [`Error::DmIoctl`] if the kernel rejects the query (e.g. the device
    /// doesn't exist — `ENXIO`).
    pub fn status(&self) -> Result<Status, Error> {
        let mut header = DmHeader::by_dev(self.dev_t.to_dev_t());
        DM_DEV_STATUS.ioctl(&*self.control, &mut header).map_err(|source| Error::DmIoctl {
            op: "DM_DEV_STATUS",
            source,
            table_line: None,
        })?;
        check_version("DM_DEV_STATUS", &header)?;
        Ok(Status::from_header(&header))
    }

    /// `DM_TABLE_STATUS` in table mode (`STATUSTYPE_TABLE`) — the active
    /// table's construction params, one [`Row<mode::Spec>`] per target.
    /// Reconstruct a target with [`Row::parse`].
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn table(&self) -> Result<impl Iterator<Item = Row<mode::Spec>>, Error> {
        let mut header = DmHeader::by_dev(self.dev_t.to_dev_t());
        header.set_status_table();
        self.table_status_iter(header)
    }

    /// `DM_TABLE_STATUS` in info mode (`STATUSTYPE_INFO`) — per-target
    /// runtime status, one [`Row<mode::Info>`] per target. Decode with
    /// [`Row::parse`].
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn info(&self) -> Result<impl Iterator<Item = Row<mode::Info>>, Error> {
        let header = DmHeader::by_dev(self.dev_t.to_dev_t());
        self.table_status_iter(header)
    }

    #[allow(clippy::large_types_passed_by_value)] // DmHeader is a cheap Copy value, not "large"
    fn table_status_iter<M: mode::Mode>(
        &self,
        header: DmHeader,
    ) -> Result<crate::table::TableStatusIter<M>, Error> {
        let buf = crate::control::ioctl_with_growing_buffer(
            &self.control,
            "DM_TABLE_STATUS",
            |fd, h| crate::uapi::DM_TABLE_STATUS.ioctl(fd, h),
            header,
            &[],
            4096,
        )?;
        let (parsed, _): (&DmHeader, _) =
            zerocopy::FromBytes::ref_from_prefix(&buf).expect("buf is at least DmHeader::SIZE bytes");
        let target_count = parsed.target_count();
        let data_start = (parsed.data_start() as usize).min(buf.len());
        Ok(crate::table::TableStatusIter::new(buf, data_start, target_count))
    }

    /// `DM_TARGET_MSG` — send a target-specific message string to whichever
    /// target covers `sector` in this device's active table. Returns the
    /// reply string if the target produced one (most messages don't).
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] if `message` contains a NUL byte; otherwise
    /// [`Error::DmIoctl`] if the kernel rejects the message.
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn message(&self, sector: u64, message: &str) -> Result<Option<String>, Error> {
        // The message is a NUL-terminated string; an interior NUL would
        // silently truncate the command the target sees. Reject it (as the
        // table builder and name/uuid paths do). Whitespace is legitimate —
        // messages are space-separated commands.
        if message.as_bytes().contains(&0) {
            return Err(Error::Usage("dm target message contains a NUL byte".into()));
        }
        let header = DmHeader::by_dev(self.dev_t.to_dev_t());
        let mut payload = Vec::with_capacity(8 + message.len() + 1);
        payload.extend_from_slice(&sector.to_ne_bytes());
        payload.extend_from_slice(message.as_bytes());
        payload.push(0);

        let buf = crate::control::ioctl_with_growing_buffer(
            &self.control,
            "DM_TARGET_MSG",
            |fd, h| crate::uapi::DM_TARGET_MSG.ioctl(fd, h),
            header,
            &payload,
            4096,
        )?;
        Ok(parse_message_reply(&buf))
    }
}

/// Extracts `DM_TARGET_MSG`'s reply string (if any) from a response
/// buffer. Split out from [`Device::message`] so the parsing logic is
/// unit-testable against a synthetic buffer, without a real ioctl.
fn parse_message_reply(buf: &[u8]) -> Option<String> {
    let (parsed, _): (&DmHeader, _) =
        zerocopy::FromBytes::ref_from_prefix(buf).expect("buf is at least DmHeader::SIZE bytes");
    if parsed.flags() & crate::uapi::DM_DATA_OUT_FLAG == 0 {
        return None;
    }
    // `data_start`/`data_size` are kernel-populated and taken on trust
    // nowhere else in this crate without a bound: clamp both to the actual
    // buffer so a buggy or hostile response (e.g. `data_start > data_size`,
    // or `data_size` past the buffer end) yields `None` instead of a
    // panicking slice. `Control::list`/`table`/`info` bound their reads the
    // same way via the iterator loop; this is the one direct-slice path.
    let len = buf.len();
    let start = (parsed.data_start() as usize).min(len);
    let end = (parsed.data_size() as usize).min(len);
    if start >= end {
        return None;
    }
    let reply = &buf[start..end];
    let nul = reply.iter().position(|&b| b == 0).unwrap_or(reply.len());
    Some(String::from_utf8_lossy(&reply[..nul]).into_owned())
}

/// The auto-removing wrapper [`crate::Control::create`] returns. `Drop`
/// performs the same removal as [`Device::remove`] but discards errors —
/// use `Device::from(removed).remove()` for observable-error removal, or
/// `Device::from(removed)` (`.into()`) alone to opt out of removal
/// entirely and keep using the device.
///
/// `#[must_use]`: dropping a `Removed` immediately removes the device, so a
/// discarded value (`let _ = control.create(name)?;`) would silently tear
/// down the device it just created. Bind it to a name to keep the device
/// alive for the binding's scope.
#[must_use = "dropping a `Removed` removes the device; bind it to keep the device alive"]
pub struct Removed(Option<Device>);

impl std::fmt::Debug for Removed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Removed").field(&self.0).finish()
    }
}

impl From<Device> for Removed {
    fn from(device: Device) -> Self {
        Removed(Some(device))
    }
}

impl From<Removed> for Device {
    fn from(mut removed: Removed) -> Self {
        removed.0.take().unwrap()
    }
}

impl std::ops::Deref for Removed {
    type Target = Device;
    fn deref(&self) -> &Device {
        self.0.as_ref().unwrap()
    }
}

impl Drop for Removed {
    fn drop(&mut self) {
        if let Some(device) = self.0.take() {
            let _ = device.remove();
        }
    }
}

/// `DM_DEV_STATUS`'s fixed-size fields. Read-only: obtained from
/// [`Device::status`] / [`crate::Control::by_name`] / [`crate::Control::by_uuid`],
/// never constructed by the caller. Fields are private behind accessors so
/// the struct can grow (it is `#[non_exhaustive]`) without breaking callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Status {
    open_count: i32,
    target_count: u32,
    event_nr: u32,
    flags: u32,
}

impl Status {
    pub(crate) fn from_header(header: &DmHeader) -> Self {
        Self {
            open_count: header.open_count(),
            target_count: header.target_count(),
            event_nr: header.event_nr(),
            flags: header.flags(),
        }
    }

    /// Number of open references to the device. Signed to match the
    /// kernel's `dm_ioctl.open_count`.
    pub fn open_count(self) -> i32 {
        self.open_count
    }

    /// Number of targets in the active table.
    pub fn target_count(self) -> u32 {
        self.target_count
    }

    /// The device's current event number (see `DM_DEV_WAIT`).
    pub fn event_nr(self) -> u32 {
        self.event_nr
    }

    /// The raw `dm_ioctl.flags` word, for bits this type has no predicate
    /// for. Prefer the named predicates below.
    pub fn flags(self) -> u32 {
        self.flags
    }

    /// The device is read-only (`DM_READONLY_FLAG`).
    pub fn is_read_only(self) -> bool {
        self.flags & DM_READONLY_FLAG != 0
    }

    /// The device is suspended (`DM_SUSPEND_FLAG`).
    pub fn is_suspended(self) -> bool {
        self.flags & DM_SUSPEND_FLAG != 0
    }

    /// An active table is present (`DM_ACTIVE_PRESENT_FLAG`).
    pub fn has_active_table(self) -> bool {
        self.flags & DM_ACTIVE_PRESENT_FLAG != 0
    }

    /// An inactive (staged) table is present (`DM_INACTIVE_PRESENT_FLAG`).
    pub fn has_inactive_table(self) -> bool {
        self.flags & DM_INACTIVE_PRESENT_FLAG != 0
    }

    /// A uevent was generated for the last operation
    /// (`DM_UEVENT_GENERATED_FLAG`).
    pub fn uevent_generated(self) -> bool {
        self.flags & DM_UEVENT_GENERATED_FLAG != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    #[test]
    fn removed_derefs_to_the_inner_device() {
        let removed = Removed::from(Device::new(DevId::new(252, 5), dummy_control()));
        // Reached through Deref<Target = Device>.
        assert_eq!(removed.id(), DevId::new(252, 5));
    }

    #[test]
    fn converting_removed_into_device_yields_the_inner_device() {
        // From<Removed> for Device takes the inner Device out (disarming the
        // drop-based removal) and hands it back intact.
        let removed = Removed::from(Device::new(DevId::new(252, 7), dummy_control()));
        let device: Device = removed.into();
        assert_eq!(device.id(), DevId::new(252, 7));
    }

    #[test]
    fn dev_id_round_trips() {
        for (major, minor) in [(0u32, 0u32), (252, 5), (7, 0), (0xfff, 0xf_ffff), (1, 1)] {
            let id = DevId::new(major, minor);
            assert_eq!(DevId::from_dev_t(id.to_dev_t()), id, "major={major} minor={minor}");
        }
    }

    #[test]
    fn dev_id_matches_known_bit_layout() {
        // Pin the packing against concrete constants, not just a round trip
        // (which can't catch an encode/decode pair that share the same bug).
        // 252 = 0xfc, minor 5 -> 0xfc05 in the classic packed encoding.
        assert_eq!(DevId::new(252, 5).to_dev_t(), 0xfc05);
        assert_eq!(DevId::from_dev_t(0xfc05), DevId::new(252, 5));

        // A minor large enough to spill into the high bits [31:20].
        // major=1 -> [19:8], minor=0x12345 -> low 8 at [7:0], high 12 at [31:20].
        assert_eq!(DevId::new(1, 0x1_2345).to_dev_t(), 0x1230_0145);
        assert_eq!(DevId::from_dev_t(0x1230_0145), DevId::new(1, 0x1_2345));
    }

    #[test]
    fn from_dev_t_truncates_high_64_bits() {
        // from_dev_t operates on the low 32 bits only; garbage above bit 31
        // in the kernel-returned u64 must not leak into the result.
        assert_eq!(DevId::from_dev_t(0xffff_ffff_0000_fc05), DevId::new(252, 5));
    }

    #[test]
    fn dev_id_display_uses_kernel_syntax() {
        assert_eq!(DevId::new(252, 5).to_string(), "252:5");
        assert_eq!(DevId::from((7, 0)).to_string(), "7:0");
    }

    /// Hand-builds a synthetic `DM_TARGET_MSG` response buffer, poking
    /// `dm_ioctl_raw`'s fields directly by byte offset rather than going
    /// through `DmHeader`'s typed API (which has no public flags/
    /// `data_start`/`data_size` setters — those are only ever set by the
    /// kernel on a real response).
    fn synthetic_message_response(data_out: bool, reply: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; DmHeader::SIZE + reply.len()];
        if data_out {
            buf[28..32].copy_from_slice(&crate::uapi::DM_DATA_OUT_FLAG.to_ne_bytes());
        }
        #[allow(clippy::cast_possible_truncation)] // test fixture, sizes are tiny
        {
            buf[16..20].copy_from_slice(&(DmHeader::SIZE as u32).to_ne_bytes());
            buf[12..16].copy_from_slice(&((DmHeader::SIZE + reply.len()) as u32).to_ne_bytes());
        }
        buf[DmHeader::SIZE..].copy_from_slice(reply);
        buf
    }

    #[test]
    fn parse_message_reply_returns_none_without_data_out_flag() {
        let buf = synthetic_message_response(false, b"ignored\0");
        assert_eq!(parse_message_reply(&buf), None);
    }

    #[test]
    fn parse_message_reply_extracts_nul_terminated_reply_string() {
        let buf = synthetic_message_response(true, b"hello\0trailing-garbage-past-nul");
        assert_eq!(parse_message_reply(&buf), Some("hello".to_string()));
    }

    #[test]
    fn parse_message_reply_handles_a_reply_with_no_nul_terminator() {
        let buf = synthetic_message_response(true, b"no-nul-here");
        assert_eq!(parse_message_reply(&buf), Some("no-nul-here".to_string()));
    }

    /// A full-size buffer whose `data_start`/`data_size` fields are set to
    /// caller-supplied values, poked directly by byte offset (as
    /// `synthetic_message_response` does). `DM_DATA_OUT_FLAG` is always set
    /// so the field-clamping path is exercised.
    #[allow(clippy::cast_possible_truncation)] // test fixture, sizes are tiny
    fn message_response_with_data_bounds(data_start: usize, data_size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; DmHeader::SIZE + 16];
        buf[28..32].copy_from_slice(&crate::uapi::DM_DATA_OUT_FLAG.to_ne_bytes());
        buf[16..20].copy_from_slice(&(data_start as u32).to_ne_bytes());
        buf[12..16].copy_from_slice(&(data_size as u32).to_ne_bytes());
        buf
    }

    #[test]
    fn parse_message_reply_returns_none_when_data_start_exceeds_data_size() {
        // data_start > data_size would panic a naive `&buf[start..end]`.
        let buf = message_response_with_data_bounds(DmHeader::SIZE + 8, DmHeader::SIZE);
        assert_eq!(parse_message_reply(&buf), None);
    }

    #[test]
    fn parse_message_reply_clamps_data_size_past_the_buffer_end() {
        // data_size far past buf.len() would panic an out-of-bounds slice;
        // it must be clamped to the actual buffer instead.
        let buf = message_response_with_data_bounds(DmHeader::SIZE, u32::MAX as usize);
        // Bytes past the header are zero, so the clamped-but-empty reply is
        // an empty string (NUL at position 0), not a panic.
        assert_eq!(parse_message_reply(&buf), Some(String::new()));
    }

    #[test]
    fn parse_message_reply_returns_none_when_both_bounds_past_buffer() {
        let buf = message_response_with_data_bounds(u32::MAX as usize, u32::MAX as usize);
        // Both clamp to buf.len(), so start >= end -> None.
        assert_eq!(parse_message_reply(&buf), None);
    }
}
