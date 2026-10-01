// SPDX-License-Identifier: Apache-2.0

//! [`Control`]: the device-mapper control fd. A factory for [`Device`]s —
//! every other operation lives on `Device` itself.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Arc;

use zerocopy::IntoBytes;

use crate::DevId;
use crate::target::Version;

use crate::device::{Device, Status, check_version, decode_dev_t};
use crate::header::DmHeader;
use crate::uapi::{DM_BUFFER_FULL_FLAG, DM_DEV_CREATE, DM_DEV_STATUS, DM_LIST_DEVICES};

/// Issue a `WriteRead` dm ioctl over a growing byte buffer, retrying with
/// a doubled buffer while the kernel reports `DM_BUFFER_FULL_FLAG`. Used
/// by `Control::devices`, `Device::table`/`Device::info`, and the rename
/// operations — every ioctl with variable-length output.
///
/// `payload` is written immediately after the header on every attempt
/// (including retries) — used by rename operations to carry the new name
/// or uuid; callers without a payload pass `&[]`.
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
    ioctl: impl Fn(&File, &mut DmHeader) -> std::io::Result<std::os::raw::c_uint>,
    header: DmHeader,
    payload: &[u8],
    initial_cap: usize,
) -> io::Result<Vec<u8>> {
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
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "short dm ioctl buffer"))?;
        let header_mut: &mut DmHeader = header_mut;
        ioctl(control, header_mut)?;

        check_version(header_mut)?;

        if header_mut.flags() & DM_BUFFER_FULL_FLAG != 0 {
            cap *= 2;
            continue;
        }
        return Ok(buf);
    }
}

/// Handle to `/dev/mapper/control` for creating and finding [`Device`]s,
/// discovering target types, and watching device-mapper events. Operations
/// on an individual device live on [`Device`]. Clones share the same fd.
#[derive(Clone, Debug)]
pub struct Control(Arc<File>);

impl Control {
    /// Open `/dev/mapper/control`.
    ///
    /// Opening the control node usually requires `CAP_SYS_ADMIN`.
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mapper/control")?;
        Ok(Self(Arc::new(file)))
    }

    /// `DM_DEV_CREATE`.
    ///
    /// The device outlives the returned handle, and this process: it is
    /// live kernel state until something removes it. Use [`Device::guard`]
    /// for scoped cleanup, or [`Device::remove`] to remove it explicitly
    /// (passing `true` for kernel-managed deferred removal).
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `name` contains a NUL byte or is too long.
    pub fn create(&self, name: &str) -> io::Result<Device> {
        let mut header = DmHeader::by_name(name)?;
        DM_DEV_CREATE.ioctl(&*self.0, &mut header)?;
        check_version(&header)?;
        Ok(Device::new(decode_dev_t(header.dev()), Arc::clone(&self.0)))
    }

    /// Wraps an already-known [`DevId`] without a syscall or liveness check.
    /// An operation on the returned handle may fail if the device is absent.
    pub fn by_device(&self, id: DevId) -> Device {
        Device::new(id, Arc::clone(&self.0))
    }

    /// Resolves a block-device path from its metadata and wraps its ID.
    ///
    /// Does not check that the block device is a live device-mapper mapping;
    /// subsequent operations ask the kernel to resolve it.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a non-block device, or `InvalidData` for an
    /// unsupported device number.
    pub fn by_node(&self, path: impl AsRef<Path>) -> io::Result<Device> {
        Ok(self.by_device(std::fs::metadata(path)?.try_into()?))
    }
    #[allow(clippy::large_types_passed_by_value)] // DmHeader is a cheap Copy value, not "large"
    fn status_lookup(&self, header: DmHeader) -> io::Result<(Device, Status)> {
        let mut header = header;
        DM_DEV_STATUS.ioctl(&*self.0, &mut header)?;
        check_version(&header)?;
        let device = Device::new(decode_dev_t(header.dev()), Arc::clone(&self.0));
        Ok((device, Status::from_header(&header)))
    }

    /// `DM_DEV_STATUS` by name. `Status` comes from the same lookup, not
    /// a second call.
    pub fn by_name(&self, name: &str) -> io::Result<(Device, Status)> {
        self.status_lookup(DmHeader::by_name(name)?)
    }

    /// `DM_DEV_STATUS` by uuid.
    pub fn by_uuid(&self, uuid: &str) -> io::Result<(Device, Status)> {
        self.status_lookup(DmHeader::by_uuid(uuid)?)
    }

    /// `DM_DEV_ARM_POLL` — arm this control fd so that `poll()`/`epoll()`
    /// reports it readable once the device-mapper subsystem next changes.
    ///
    /// Readiness means some device-mapper event occurred; it does not identify
    /// the device. The armed state belongs to this fd and is shared by
    /// [`Control`] clones. Readiness persists until the fd is re-armed;
    /// re-arming also discards any pending readiness.
    ///
    /// Register the fd with a reactor using [`AsFd`](std::os::fd::AsFd):
    ///
    /// ```no_run
    /// use std::os::fd::AsFd as _;
    /// # fn watch(control: &devmap_linux::Control) -> std::io::Result<()> {
    /// control.arm_poll()?;
    /// let fd = control.as_fd(); // Register with poll/epoll before waiting.
    /// # let _ = fd;
    /// # Ok(()) }
    /// ```
    pub fn arm_poll(&self) -> io::Result<()> {
        let mut header = DmHeader::any();
        crate::uapi::DM_DEV_ARM_POLL.ioctl(&*self.0, &mut header)?;
        check_version(&header)
    }

    /// Shared body of [`Control::rename`] and [`Control::set_uuid`]:
    /// `DM_DEV_RENAME` identifies the device by its *current name* (the
    /// kernel looks it up in the name hash), and carries the replacement
    /// string in the data area.
    fn rename_inner(&self, current_name: &str, new: &str, as_uuid: bool) -> io::Result<Device> {
        if new.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dm rename target contains a NUL byte",
            ));
        }
        let limit = if as_uuid {
            crate::uapi::DM_UUID_LEN
        } else {
            crate::uapi::DM_NAME_LEN
        };
        if new.len() >= limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "dm rename target too long: {} bytes (max {})",
                    new.len(),
                    limit - 1
                ),
            ));
        }

        let mut header = DmHeader::by_name(current_name)?;
        if as_uuid {
            header.set_uuid_flag();
        }
        let mut payload = Vec::with_capacity(new.len() + 1);
        payload.extend_from_slice(new.as_bytes());
        payload.push(0);

        let buf = ioctl_with_growing_buffer(
            &self.0,
            |fd, h| crate::uapi::DM_DEV_RENAME.ioctl(fd, h),
            header,
            &payload,
            4096,
        )?;
        let parsed = DmHeader::response(&buf)?;
        Ok(Device::new(decode_dev_t(parsed.dev()), Arc::clone(&self.0)))
    }

    /// `DM_DEV_RENAME` — give the device currently called `current_name`
    /// the name `new_name`.
    ///
    /// Keyed by name rather than [`DevId`] because that is how the kernel
    /// resolves it: `dm_hash_rename` looks the device up in the name hash,
    /// so this lives on `Control` rather than [`Device`].
    ///
    /// # Errors
    ///
    /// `InvalidInput` if either name contains a NUL byte or is too long.
    pub fn rename(&self, current_name: &str, new_name: &str) -> io::Result<Device> {
        self.rename_inner(current_name, new_name, false)
    }

    /// `DM_DEV_RENAME` with `DM_UUID_FLAG` — attach a uuid to the device
    /// currently called `name`.
    ///
    /// A device created by [`Control::create`] has no uuid; this is the
    /// only way to give it one, and the kernel permits it exactly once —
    /// a device that already has a uuid cannot have it changed.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `name` or `uuid` contains a NUL byte or is too long.
    pub fn set_uuid(&self, name: &str, uuid: &str) -> io::Result<Device> {
        self.rename_inner(name, uuid, true)
    }

    /// `DM_LIST_VERSIONS` — target types currently registered with this kernel.
    ///
    /// This is an enumeration, not an exhaustive availability check: a
    /// target module that has not yet been loaded will not appear. Table
    /// construction queries each target by name, allowing module loading.
    pub fn versions(&self) -> io::Result<impl Iterator<Item = (String, Version)>> {
        let buf = ioctl_with_growing_buffer(
            &self.0,
            |fd, h| crate::uapi::DM_LIST_VERSIONS.ioctl(fd, h),
            DmHeader::any(),
            &[],
            4096,
        )?;
        TargetIter::new(buf)
    }

    /// `DM_LIST_DEVICES` — every registered dm device, each paired with a
    /// ready-to-use handle.
    pub fn devices(&self) -> io::Result<impl Iterator<Item = (String, Device)>> {
        let buf = ioctl_with_growing_buffer(
            &self.0,
            |fd, h| DM_LIST_DEVICES.ioctl(fd, h),
            DmHeader::any(),
            &[],
            4096,
        )?;
        let header = DmHeader::response(&buf)?;
        let start = header.data_start() as usize;
        let end = header.data_size() as usize;
        Ok(ListDevicesIter {
            buf,
            offset: start,
            end,
            control: Arc::clone(&self.0),
        })
    }
}

/// Borrow the control fd, so it can be registered with a `poll`/`epoll`
/// reactor after [`Control::arm_poll`]. The fd stays owned by the
/// `Control`.
impl std::os::fd::AsFd for Control {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl std::os::fd::AsRawFd for Control {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd as _;
        self.0.as_fd().as_raw_fd()
    }
}

/// Query one target by name. Unlike enumeration, the kernel's named lookup
/// may request the target module before returning its version.
pub(crate) fn target_version(control: &File, name: &str) -> io::Result<Version> {
    let buf = ioctl_with_growing_buffer(
        control,
        |fd, h| crate::uapi::DM_GET_TARGET_VERSION.ioctl(fd, h),
        DmHeader::by_name(name)?,
        &[],
        512,
    )?;
    TargetIter::new(buf)?
        .next()
        .filter(|(reported, _)| reported == name)
        .map(|(_, version)| version)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target version"))
}

/// Owns the ioctl buffer so iteration doesn't require a separate collection.
struct TargetIter {
    buf: Vec<u8>,
    offset: usize,
    end: usize,
}

impl TargetIter {
    fn new(buf: Vec<u8>) -> io::Result<Self> {
        let header = DmHeader::response(&buf)?;
        Ok(Self {
            offset: (header.data_start() as usize).min(buf.len()),
            end: (header.data_size() as usize).min(buf.len()),
            buf,
        })
    }
}

impl Iterator for TargetIter {
    type Item = (String, Version);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.offset;
        let name_start = start.checked_add(16)?;
        if start >= self.end || name_start > self.end {
            self.offset = self.end;
            return None;
        }
        let record = &self.buf[start..self.end];
        let next = u32::from_ne_bytes(record[0..4].try_into().unwrap());
        let version = Version::from([
            u32::from_ne_bytes(record[4..8].try_into().unwrap()),
            u32::from_ne_bytes(record[8..12].try_into().unwrap()),
            u32::from_ne_bytes(record[12..16].try_into().unwrap()),
        ]);
        let record_end = if next == 0 {
            self.end
        } else {
            start.checked_add(next as usize)?.min(self.end)
        };
        if record_end <= name_start {
            self.offset = self.end;
            return None;
        }
        let name_bytes = &self.buf[name_start..record_end];
        let nul = name_bytes.iter().position(|&b| b == 0)?;
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();

        if next == 0 {
            self.offset = self.end;
        } else {
            self.offset = start.checked_add(next as usize).unwrap_or(self.end);
            if self.offset <= start || self.offset > self.end {
                self.offset = self.end;
            }
        }
        Some((name, version))
    }
}

/// Parses `DM_LIST_DEVICES`'s response into `(name, Device)` pairs. Not
/// exported — `Control::devices()` returns `impl Iterator<...>`.
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
        // `checked_add` guards a kernel-controlled `next` from overflowing
        // `usize` on 32-bit targets (matches `TableStatusIter`); on overflow
        // we stop.
        let record_end = self.offset.checked_add(12)?;
        if self.offset >= self.end || record_end > self.buf.len() {
            return None;
        }
        let entry = &self.buf[self.offset..];
        let dev = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        let next = u32::from_ne_bytes(entry[8..12].try_into().unwrap());
        let name_bytes = &entry[12..];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        let device = Device::new(decode_dev_t(dev), Arc::clone(&self.control));

        self.offset = if next == 0 {
            self.end
        } else {
            self.offset.saturating_add(next as usize)
        };

        Some((name, device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hand-builds a synthetic `DM_LIST_DEVICES`-shaped response buffer:
    // N `dm_name_list` entries, each `next` relative to *that entry's
    // own* start (the opposite convention from `DM_TABLE_STATUS`'s
    // `dm_target_spec.next` — see `TableStatusIter`'s tests). Independent
    // of any real ioctl call, exercising the parser against a
    // kernel-shaped response rather than a round trip.
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
            let next = if i == entries.len() - 1 {
                0
            } else {
                len as u32
            };
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

    /// Hand-builds a synthetic `DM_LIST_VERSIONS` response: a chain of
    /// `dm_target_versions` records whose `next` is relative to *that
    /// record's own* start (the same convention as `dm_name_list`).
    #[allow(clippy::cast_possible_truncation)] // test fixture, sizes are tiny
    fn synthetic_versions_response(entries: &[(&str, [u32; 3])]) -> Vec<u8> {
        let start = DmHeader::SIZE;
        let lens: Vec<usize> = entries
            .iter()
            .map(|(name, _)| (16 + name.len() + 1).next_multiple_of(8))
            .collect();
        let payload_len: usize = lens.iter().sum();
        let mut buf = vec![0u8; start + payload_len];
        buf[16..20].copy_from_slice(&(start as u32).to_ne_bytes());
        buf[12..16].copy_from_slice(&((start + payload_len) as u32).to_ne_bytes());

        let mut offset = start;
        for (i, (name, version)) in entries.iter().enumerate() {
            let next = if i == entries.len() - 1 {
                0
            } else {
                lens[i] as u32
            };
            buf[offset..offset + 4].copy_from_slice(&next.to_ne_bytes());
            for (v, word) in version.iter().enumerate() {
                let off = offset + 4 + v * 4;
                buf[off..off + 4].copy_from_slice(&word.to_ne_bytes());
            }
            buf[offset + 16..offset + 16 + name.len()].copy_from_slice(name.as_bytes());
            offset += lens[i];
        }
        buf
    }

    #[test]
    fn target_iter_reads_a_single_record() {
        let buf = synthetic_versions_response(&[("linear", [1, 4, 0])]);
        assert_eq!(
            TargetIter::new(buf).unwrap().collect::<Vec<_>>(),
            [("linear".to_string(), Version::from([1, 4, 0]))]
        );
    }

    #[test]
    fn target_iter_follows_next_relative_to_current_record() {
        let buf = synthetic_versions_response(&[
            ("linear", [1, 4, 0]),
            ("striped", [1, 6, 0]),
            ("thin-pool", [1, 23, 0]),
        ]);
        let got: Vec<(String, Version)> = TargetIter::new(buf).unwrap().collect();
        assert_eq!(
            got,
            [
                ("linear".to_string(), Version::from([1, 4, 0])),
                ("striped".to_string(), Version::from([1, 6, 0])),
                ("thin-pool".to_string(), Version::from([1, 23, 0])),
            ]
        );
    }

    #[test]
    fn target_iter_yields_nothing_for_an_empty_list() {
        assert_eq!(
            TargetIter::new(synthetic_versions_response(&[]))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn target_iter_rejects_a_short_header() {
        assert_eq!(
            TargetIter::new(Vec::new()).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn target_iter_stops_on_a_truncated_final_record() {
        // `data_size` claims a record the buffer doesn't actually hold: the
        // 16-byte-header guard must stop rather than slice out of bounds.
        let mut buf = vec![0u8; DmHeader::SIZE + 8];
        #[allow(clippy::cast_possible_truncation)]
        {
            buf[16..20].copy_from_slice(&(DmHeader::SIZE as u32).to_ne_bytes());
            buf[12..16].copy_from_slice(&((DmHeader::SIZE + 100) as u32).to_ne_bytes());
        }
        assert_eq!(TargetIter::new(buf).unwrap().count(), 0);
    }

    #[test]
    #[ignore = "requires access to /dev/mapper/control"]
    fn named_target_lookup_reports_zero_version() {
        let control = Control::open().expect("open device-mapper control");
        let version = target_version(&control.0, "zero").expect("DM_GET_TARGET_VERSION for zero");
        assert_eq!(version.major, 1);
    }

    #[test]
    fn list_devices_iter_parses_single_entry() {
        let (buf, start, end) =
            synthetic_list_devices_response(&[(u64::from(DevId::new(252, 5).unwrap()), "foo")]);
        let iter = ListDevicesIter {
            buf,
            offset: start,
            end,
            control: dummy_control(),
        };
        let entries: Vec<(String, DevId)> = iter.map(|(name, dev)| (name, dev.id())).collect();
        assert_eq!(entries, [("foo".to_string(), DevId::new(252, 5).unwrap())]);
    }

    #[test]
    fn list_devices_iter_follows_next_relative_to_current_entry() {
        let (buf, start, end) = synthetic_list_devices_response(&[
            (u64::from(DevId::new(252, 5).unwrap()), "first"),
            (u64::from(DevId::new(252, 6).unwrap()), "second-longer-name"),
            (u64::from(DevId::new(252, 7).unwrap()), "third"),
        ]);
        let iter = ListDevicesIter {
            buf,
            offset: start,
            end,
            control: dummy_control(),
        };
        let entries: Vec<(String, DevId)> = iter.map(|(name, dev)| (name, dev.id())).collect();
        assert_eq!(
            entries,
            [
                ("first".to_string(), DevId::new(252, 5).unwrap()),
                (
                    "second-longer-name".to_string(),
                    DevId::new(252, 6).unwrap()
                ),
                ("third".to_string(), DevId::new(252, 7).unwrap()),
            ]
        );
    }

    #[test]
    fn list_devices_iter_yields_nothing_for_empty_list() {
        let start = DmHeader::SIZE;
        let iter = ListDevicesIter {
            buf: vec![0u8; start],
            offset: start,
            end: start,
            control: dummy_control(),
        };
        assert_eq!(iter.count(), 0);
    }

    #[test]
    fn list_devices_iter_stops_on_truncated_final_record() {
        // `end` claims a record beyond what the buffer actually holds: the
        // 12-byte-header guard must stop cleanly rather than slice OOB.
        let start = DmHeader::SIZE;
        let buf = vec![0u8; start + 8]; // only 8 bytes of a 12+-byte record
        let iter = ListDevicesIter {
            buf,
            offset: start,
            end: start + 100,
            control: dummy_control(),
        };
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
            |_fd, h| {
                h.set_major_version(crate::uapi::DM_IOCTL_VERSION_MAJOR + 1);
                Ok(0)
            },
            DmHeader::any(),
            &[],
            4096,
        )
        .expect_err("version mismatch must error");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn growing_buffer_maps_ioctl_failure_to_dm_ioctl_error() {
        let control = null_fd();
        let err = ioctl_with_growing_buffer(
            &control,
            |_fd, _h| Err(io::Error::from_raw_os_error(libc_enxio())),
            DmHeader::any(),
            &[],
            4096,
        )
        .expect_err("ioctl failure must propagate");
        assert_eq!(err.raw_os_error(), Some(libc_enxio()));
    }

    // ENXIO without pulling in the libc crate.
    fn libc_enxio() -> i32 {
        6
    }
}
