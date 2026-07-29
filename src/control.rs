// SPDX-License-Identifier: Apache-2.0

//! [`Control`]: the device-mapper control fd. A factory for [`Device`]s —
//! every other operation lives on `Device` itself.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use zerocopy::IntoBytes;

use crate::Error;
use crate::device::{DevId, Device, Removed, Status, check_version};
use crate::header::DmHeader;
use crate::uapi::{DM_BUFFER_FULL_FLAG, DM_DEV_CREATE, DM_DEV_STATUS, DM_LIST_DEVICES};

/// Issue a `WriteRead` dm ioctl over a growing byte buffer, retrying with
/// a doubled buffer while the kernel reports `DM_BUFFER_FULL_FLAG`. Used
/// by `Control::list`, `Device::table_status`, and `Device::message` —
/// every ioctl with variable-length output.
///
/// `payload` is written immediately after the header on every attempt
/// (including retries) — used by `Device::message` to carry the
/// `dm_target_msg` sector+string; the other two callers pass `&[]`.
///
/// `ioctl` is a closure rather than an `Ioctl<WriteRead, _>` value passed
/// directly: `Ioctl`'s direction markers (`Read`/`Write`/`WriteRead`)
/// don't derive `Copy`/`Clone`, so `Ioctl<WriteRead, _>` isn't actually
/// `Copy` despite the outer type deriving it — a closure that references
/// the `const DM_*` ioctl declaration re-materializes it fresh on every
/// call instead of trying to move the same value repeatedly.
// `DmHeader` is a cheap Copy value (a 312-byte plain struct, no heap data)
// deliberately passed by value here so callers don't need to manage its
// lifetime across retries; `#[allow]` because clippy's size heuristic
// doesn't distinguish "cheap to copy" from "large".
#[allow(clippy::large_types_passed_by_value)]
pub(crate) fn ioctl_with_growing_buffer(
    control: &File,
    op: &'static str,
    ioctl: impl Fn(&File, &mut DmHeader) -> std::io::Result<std::os::raw::c_uint>,
    header: DmHeader,
    payload: &[u8],
    initial_cap: usize,
) -> Result<Vec<u8>, Error> {
    let mut cap = initial_cap.max(DmHeader::SIZE + payload.len());
    loop {
        let mut buf = vec![0u8; cap];
        let mut h = header;
        // Real dm ioctl buffers never approach u32::MAX; the kernel's own
        // dm_ioctl.data_size field is itself a u32.
        #[allow(clippy::cast_possible_truncation)]
        h.set_data_size(buf.len() as u32);
        buf[..DmHeader::SIZE].copy_from_slice(h.as_bytes());
        buf[DmHeader::SIZE..DmHeader::SIZE + payload.len()].copy_from_slice(payload);

        let (header_mut, _) = zerocopy::FromBytes::mut_from_prefix(&mut buf)
            .expect("buf is at least DmHeader::SIZE bytes");
        let header_mut: &mut DmHeader = header_mut;
        ioctl(control, header_mut)
            .map_err(|source| Error::DmIoctl { op, source, table_line: None })?;

        check_version(op, header_mut)?;

        if header_mut.flags() & DM_BUFFER_FULL_FLAG != 0 {
            cap *= 2;
            continue;
        }
        return Ok(buf);
    }
}

/// The device-mapper control fd (`/dev/mapper/control`). A factory for
/// [`Device`]s — `create`/`by_device`/`by_node`/`by_name`/`by_uuid`/`list`
/// are the only things `Control` itself does; everything else (loading a
/// table, suspending, removing, querying status) is a `Device` method.
#[derive(Clone, Debug)]
pub struct Control(Arc<File>);

impl Control {
    /// Open `/dev/mapper/control`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the control node can't be opened (typically because
    /// the process lacks `CAP_SYS_ADMIN`, or device-mapper isn't loaded).
    pub fn open() -> Result<Self, Error> {
        Ok(Self(Arc::new(
            OpenOptions::new().read(true).write(true).open("/dev/mapper/control")?,
        )))
    }

    /// `DM_DEV_CREATE`. Fails with [`Error::NameConflict`] if `name` is
    /// already taken.
    ///
    /// The returned [`Removed`] removes the device when dropped — bind it to
    /// a name; do not discard it with `let _ = ...`.
    #[must_use = "the returned `Removed` removes the device when dropped; bind it to keep the device"]
    pub fn create(&self, name: &str) -> Result<Removed, Error> {
        let mut header = DmHeader::by_name(name)?;
        match DM_DEV_CREATE.ioctl(&*self.0, &mut header) {
            Ok(_) => {}
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::ResourceBusy
                ) =>
            {
                return Err(Error::NameConflict { name: name.into() });
            }
            Err(source) => {
                return Err(Error::DmIoctl { op: "DM_DEV_CREATE", source, table_line: None });
            }
        }
        check_version("DM_DEV_CREATE", &header)?;
        let device = Device::new(DevId::from_dev_t(header.dev()), Arc::clone(&self.0));
        Ok(Removed::from(device))
    }

    /// No syscall — wraps an already-known [`DevId`] (e.g. `(major, minor)`,
    /// which converts via `Into`). Does no liveness check: a real operation
    /// on the result fails with the kernel's `ENXIO` if it doesn't
    /// correspond to an actual dm device.
    pub fn by_device(&self, id: impl Into<DevId>) -> Device {
        Device::new(id.into(), Arc::clone(&self.0))
    }

    /// `stat()` only — resolves a device node path to its [`DevId`].
    pub fn by_node(&self, path: impl AsRef<Path>) -> Result<Device, Error> {
        let path = path.as_ref();
        // Attach the path to the failure: a bare `#[from] io::Error` yields
        // "io: No such file or directory" with no indication it was node
        // resolution. The original `ErrorKind` is preserved.
        let meta = std::fs::metadata(path).map_err(|source| {
            Error::Io(io::Error::new(
                source.kind(),
                format!("cannot stat device node {}: {source}", path.display()),
            ))
        })?;
        Ok(Device::new(DevId::from_dev_t(meta.rdev()), Arc::clone(&self.0)))
    }

    #[allow(clippy::large_types_passed_by_value)] // DmHeader is a cheap Copy value, not "large"
    fn status_lookup(&self, header: DmHeader) -> Result<(Device, Status), Error> {
        let mut header = header;
        DM_DEV_STATUS
            .ioctl(&*self.0, &mut header)
            .map_err(|source| Error::DmIoctl { op: "DM_DEV_STATUS", source, table_line: None })?;
        check_version("DM_DEV_STATUS", &header)?;
        let device = Device::new(DevId::from_dev_t(header.dev()), Arc::clone(&self.0));
        Ok((device, Status::from_header(&header)))
    }

    /// `DM_DEV_STATUS` by name. `Status` comes from the same lookup, not
    /// a second call.
    pub fn by_name(&self, name: &str) -> Result<(Device, Status), Error> {
        self.status_lookup(DmHeader::by_name(name)?)
    }

    /// `DM_DEV_STATUS` by uuid.
    pub fn by_uuid(&self, uuid: &str) -> Result<(Device, Status), Error> {
        self.status_lookup(DmHeader::by_uuid(uuid)?)
    }

    /// `DM_LIST_DEVICES` — every registered dm device, each paired with a
    /// ready-to-use handle.
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn list(&self) -> Result<impl Iterator<Item = (String, Device)>, Error> {
        let buf = ioctl_with_growing_buffer(
            &self.0,
            "DM_LIST_DEVICES",
            |fd, h| DM_LIST_DEVICES.ioctl(fd, h),
            DmHeader::any(),
            &[],
            4096,
        )?;
        let (header, _): (&DmHeader, _) =
            zerocopy::FromBytes::ref_from_prefix(&buf).expect("buf is at least DmHeader::SIZE bytes");
        let start = header.data_start() as usize;
        let end = header.data_size() as usize;
        Ok(ListDevicesIter { buf, offset: start, end, control: Arc::clone(&self.0) })
    }
}

/// Parses `DM_LIST_DEVICES`'s response into `(name, Device)` pairs. Not
/// exported — `Control::list()` returns `impl Iterator<...>`.
///
/// `dm_name_list.next` is the byte offset from *this* record's start to
/// the next one (unlike `dm_target_spec.next` on `DM_TABLE_STATUS`, which
/// is relative to the first record — see `<linux/dm-ioctl.h>`).
struct ListDevicesIter {
    buf: Vec<u8>,
    offset: usize,
    end: usize,
    control: Arc<File>,
}

impl Iterator for ListDevicesIter {
    type Item = (String, Device);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.end || self.offset + 12 > self.buf.len() {
            return None;
        }
        let entry = &self.buf[self.offset..];
        let dev = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        let next = u32::from_ne_bytes(entry[8..12].try_into().unwrap());
        let name_bytes = &entry[12..];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        let device = Device::new(DevId::from_dev_t(dev), Arc::clone(&self.control));

        self.offset = if next == 0 { self.end } else { self.offset + next as usize };

        Some((name, device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-builds a synthetic `DM_LIST_DEVICES`-shaped response buffer:
    /// N `dm_name_list` entries, each `next` relative to *that entry's
    /// own* start (the opposite convention from `DM_TABLE_STATUS`'s
    /// `dm_target_spec.next` — see `TableStatusIter`'s tests). Independent
    /// of any real ioctl call, since this is testing the parser against
    /// what a real kernel response looks like, not a round trip.
    // Test-only helper building tiny fixture buffers; lengths never approach u32::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_list_devices_response(entries: &[(u64, &str)]) -> (Vec<u8>, usize, usize) {
        let start = DmHeader::SIZE;
        let mut lens = Vec::with_capacity(entries.len());
        let mut payload_len = 0usize;
        for (_, name) in entries {
            // 8 (dev) + 4 (next) + name + NUL, 8-byte aligned (matches
            // real dm_name_list chaining in practice, though the kernel
            // doesn't strictly require alignment for the *last* entry).
            let len = (12 + name.len() + 1).next_multiple_of(8);
            lens.push(len);
            payload_len += len;
        }
        let mut bytes = vec![0u8; start + payload_len];

        let mut offset = start;
        for (i, (dev, name)) in entries.iter().enumerate() {
            let len = lens[i];
            let next = if i == entries.len() - 1 { 0 } else { len as u32 };
            bytes[offset..offset + 8].copy_from_slice(&dev.to_ne_bytes());
            bytes[offset + 8..offset + 12].copy_from_slice(&next.to_ne_bytes());
            bytes[offset + 12..offset + 12 + name.len()].copy_from_slice(name.as_bytes());
            offset += len;
        }

        (bytes, start, start + payload_len)
    }

    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    #[test]
    fn list_devices_iter_parses_single_entry() {
        let (buf, start, end) = synthetic_list_devices_response(&[(DevId::new(252, 5).to_dev_t(), "foo")]);
        let iter = ListDevicesIter { buf, offset: start, end, control: dummy_control() };
        let entries: Vec<(String, DevId)> = iter.map(|(name, dev)| (name, dev.id())).collect();
        assert_eq!(entries, [("foo".to_string(), DevId::new(252, 5))]);
    }

    #[test]
    fn list_devices_iter_follows_next_relative_to_current_entry() {
        let (buf, start, end) = synthetic_list_devices_response(&[
            (DevId::new(252, 5).to_dev_t(), "first"),
            (DevId::new(252, 6).to_dev_t(), "second-longer-name"),
            (DevId::new(252, 7).to_dev_t(), "third"),
        ]);
        let iter = ListDevicesIter { buf, offset: start, end, control: dummy_control() };
        let entries: Vec<(String, DevId)> = iter.map(|(name, dev)| (name, dev.id())).collect();
        assert_eq!(
            entries,
            [
                ("first".to_string(), DevId::new(252, 5)),
                ("second-longer-name".to_string(), DevId::new(252, 6)),
                ("third".to_string(), DevId::new(252, 7)),
            ]
        );
    }

    #[test]
    fn list_devices_iter_yields_nothing_for_empty_list() {
        let start = DmHeader::SIZE;
        let iter = ListDevicesIter { buf: vec![0u8; start], offset: start, end: start, control: dummy_control() };
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn list_devices_iter_stops_on_truncated_final_record() {
        // `end` claims a record beyond what the buffer actually holds: the
        // 12-byte-header guard must stop cleanly rather than slice OOB.
        let start = DmHeader::SIZE;
        let buf = vec![0u8; start + 8]; // only 8 bytes of a 12+-byte record
        let iter = ListDevicesIter { buf, offset: start, end: start + 100, control: dummy_control() };
        assert_eq!(iter.count(), 0);
    }

    /// A `/dev/null` handle standing in for the control fd; the fake ioctl
    /// closures below never actually touch it.
    fn null_fd() -> File {
        File::open("/dev/null").expect("/dev/null always exists")
    }

    #[test]
    fn growing_buffer_retries_on_buffer_full_then_succeeds() {
        let control = null_fd();
        let calls = std::cell::Cell::new(0u32);
        let buf = ioctl_with_growing_buffer(
            &control,
            "TEST",
            |_fd, h| {
                let n = calls.get();
                calls.set(n + 1);
                // First call: report the buffer was too small. Second: clear.
                h.set_flags_raw(if n == 0 { DM_BUFFER_FULL_FLAG } else { 0 });
                Ok(0)
            },
            DmHeader::any(),
            &[],
            4096,
        )
        .expect("second attempt succeeds");
        assert_eq!(calls.get(), 2, "should retry exactly once");
        assert!(buf.len() >= 8192, "capacity should have doubled from 4096");
    }

    #[test]
    fn growing_buffer_rejects_version_mismatch() {
        let control = null_fd();
        let err = ioctl_with_growing_buffer(
            &control,
            "TEST",
            |_fd, h| {
                h.set_major_version(crate::uapi::DM_IOCTL_VERSION_MAJOR + 1);
                Ok(0)
            },
            DmHeader::any(),
            &[],
            4096,
        )
        .expect_err("version mismatch must error");
        match err {
            Error::DmIoctl { op, source, table_line } => {
                assert_eq!(op, "TEST");
                assert_eq!(source.kind(), io::ErrorKind::Unsupported);
                assert!(table_line.is_none());
            }
            other => panic!("expected DmIoctl, got {other:?}"),
        }
    }

    #[test]
    fn growing_buffer_maps_ioctl_failure_to_dm_ioctl_error() {
        let control = null_fd();
        let err = ioctl_with_growing_buffer(
            &control,
            "TEST",
            |_fd, _h| Err(io::Error::from_raw_os_error(libc_enxio())),
            DmHeader::any(),
            &[],
            4096,
        )
        .expect_err("ioctl failure must propagate");
        match err {
            Error::DmIoctl { op, .. } => assert_eq!(op, "TEST"),
            other => panic!("expected DmIoctl, got {other:?}"),
        }
    }

    // ENXIO without pulling in the libc crate.
    fn libc_enxio() -> i32 {
        6
    }
}
