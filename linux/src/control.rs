// SPDX-License-Identifier: Apache-2.0

//! [`Control`]: the device-mapper control fd. A factory for [`Device`]s —
//! every other operation lives on `Device` itself.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use zerocopy::IntoBytes;

use crate::device::{DevId, Device, Removed, Status, check_version};
use crate::header::DmHeader;
use crate::uapi::{DM_BUFFER_FULL_FLAG, DM_DEV_CREATE, DM_DEV_STATUS, DM_LIST_DEVICES};

/// Issue a `WriteRead` dm ioctl over a growing byte buffer, retrying with
/// a doubled buffer while the kernel reports `DM_BUFFER_FULL_FLAG`. Used
/// by `Control::list`, `Device::table`/`Device::info`, and `Device::message` —
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
            .expect("buf is at least DmHeader::SIZE bytes");
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
    /// The underlying `io::Error` if the control node can't be opened
    /// (typically `PermissionDenied` because the process lacks
    /// `CAP_SYS_ADMIN`, or `NotFound` if device-mapper isn't loaded).
    pub fn open() -> io::Result<Self> {
        // Propagate the raw io::Error so its errno (and kind) survive; the
        // likely-cause hint lives in the `# Errors` docs, not the message.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mapper/control")?;
        Ok(Self(Arc::new(file)))
    }

    /// `DM_DEV_CREATE`.
    ///
    /// # Errors
    ///
    /// The kernel's `io::Error` if the create fails: `AlreadyExists`
    /// (`EEXIST`) or `ResourceBusy` (`EBUSY`) if `name` is already taken,
    /// `InvalidInput` if `name` has a NUL byte or is too long, or
    /// `Unsupported` if the kernel dm-ioctl version differs.
    ///
    /// The returned [`Removed`] removes the device when dropped — bind it to
    /// a name; do not discard it with `let _ = ...`.
    #[must_use = "the returned `Removed` removes the device when dropped; bind it to keep the device"]
    pub fn create(&self, name: &str) -> io::Result<Removed> {
        let mut header = DmHeader::by_name(name)?;
        DM_DEV_CREATE.ioctl(&*self.0, &mut header)?;
        check_version(&header)?;
        let device = Device::new(DevId::from_dev_t(header.dev()), Arc::clone(&self.0));
        Ok(Removed::from(device))
    }

    /// No syscall — wraps an already-known [`DevId`] (build one with
    /// [`DevId::new`]). Does no liveness check:
    /// a real operation on the result fails with the kernel's `ENXIO` if it
    /// doesn't correspond to an actual dm device.
    pub fn by_device(&self, id: DevId) -> Device {
        Device::new(id, Arc::clone(&self.0))
    }

    /// `stat()` only — resolves a device node path to its [`DevId`].
    ///
    /// # Errors
    ///
    /// The underlying `io::Error` if the path can't be `stat`ed (its errno
    /// and kind are preserved).
    pub fn by_node(&self, path: impl AsRef<Path>) -> io::Result<Device> {
        let meta = std::fs::metadata(path)?;
        Ok(Device::new(
            DevId::from_dev_t(meta.rdev()),
            Arc::clone(&self.0),
        ))
    }

    #[allow(clippy::large_types_passed_by_value)] // DmHeader is a cheap Copy value, not "large"
    fn status_lookup(&self, header: DmHeader) -> io::Result<(Device, Status)> {
        let mut header = header;
        DM_DEV_STATUS.ioctl(&*self.0, &mut header)?;
        check_version(&header)?;
        let device = Device::new(DevId::from_dev_t(header.dev()), Arc::clone(&self.0));
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
        let (parsed, _): (&DmHeader, _) = zerocopy::FromBytes::ref_from_prefix(&buf)
            .expect("buf is at least DmHeader::SIZE bytes");
        Ok(Device::new(
            DevId::from_dev_t(parsed.dev()),
            Arc::clone(&self.0),
        ))
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
    /// `InvalidInput` if `new_name` has a NUL byte or is too long;
    /// otherwise the kernel's `io::Error` — `NotFound` (`ENXIO`) if no
    /// device has `current_name`, `AlreadyExists` (`EBUSY`) if `new_name`
    /// is taken, or `InvalidInput` (`EINVAL`) if the kernel rejects the
    /// name (it forbids `/`, `.`, and `..`).
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn rename(&self, current_name: &str, new_name: &str) -> io::Result<Device> {
        self.rename_inner(current_name, new_name, false)
    }

    /// `DM_DEV_RENAME` with `DM_UUID_FLAG` — attach a uuid to the device
    /// currently called `name`.
    ///
    /// A device created by [`Control::create`] has no uuid;  this is the
    /// only way to give it one, and the kernel permits it exactly once —
    /// a device that already has a uuid cannot have it changed.
    ///
    /// # Errors
    ///
    /// As [`Control::rename`], plus the kernel's `InvalidInput`
    /// (`EINVAL`) if the device already has a uuid.
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn set_uuid(&self, name: &str, uuid: &str) -> io::Result<Device> {
        self.rename_inner(name, uuid, true)
    }

    /// `DM_LIST_VERSIONS` — every target type this kernel has registered,
    /// with its version.
    ///
    /// Lets a caller check a target is available before building a table
    /// for it, rather than discovering it via `EINVAL` from
    /// `DM_TABLE_LOAD`. Targets are registered on module load, so a target
    /// whose module is not yet loaded will not appear.
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    ///
    /// # Errors
    ///
    /// The kernel's `io::Error` if it rejects the query.
    pub fn list_versions(&self) -> io::Result<Vec<TargetVersion>> {
        let buf = ioctl_with_growing_buffer(
            &self.0,
            |fd, h| crate::uapi::DM_LIST_VERSIONS.ioctl(fd, h),
            DmHeader::any(),
            &[],
            4096,
        )?;
        Ok(parse_versions(&buf))
    }

    /// `DM_LIST_DEVICES` — every registered dm device, each paired with a
    /// ready-to-use handle.
    ///
    /// # Panics
    ///
    /// Never in practice: panics only if the kernel returned fewer than
    /// `DmHeader::SIZE` bytes for a `WriteRead` ioctl, which would itself
    /// indicate a kernel bug.
    pub fn list(&self) -> io::Result<impl Iterator<Item = (String, Device)>> {
        let buf = ioctl_with_growing_buffer(
            &self.0,
            |fd, h| DM_LIST_DEVICES.ioctl(fd, h),
            DmHeader::any(),
            &[],
            4096,
        )?;
        let (header, _): (&DmHeader, _) = zerocopy::FromBytes::ref_from_prefix(&buf)
            .expect("buf is at least DmHeader::SIZE bytes");
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

/// One registered dm target type and its version, from
/// [`Control::list_versions`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetVersion {
    /// The kernel `target_type` name, e.g. `"linear"` — matches
    /// [`crate::Target::NAME`].
    pub name: String,
    /// The target's `[major, minor, patch]` version.
    pub version: [u32; 3],
}

/// Parses `DM_LIST_VERSIONS`' response into [`TargetVersion`]s.
///
/// The payload is a chain of `struct dm_target_versions`: a `u32` `next`
/// (byte offset from *this* record's start to the following one, 0 on the
/// last), a `u32[3]` version, then a NUL-terminated name. Split out from
/// [`Control::list_versions`] so it is unit-testable against a synthetic
/// buffer, and every read is bounded by the actual buffer.
fn parse_versions(buf: &[u8]) -> Vec<TargetVersion> {
    let (header, _): (&DmHeader, _) =
        zerocopy::FromBytes::ref_from_prefix(buf).expect("buf is at least DmHeader::SIZE bytes");
    let end = (header.data_size() as usize).min(buf.len());
    let mut offset = (header.data_start() as usize).min(buf.len());

    let mut out = Vec::new();
    loop {
        // `next` plus the three version words must both be present.
        let Some(name_start) = offset.checked_add(16) else {
            return out;
        };
        if offset >= end || name_start > buf.len() {
            return out;
        }
        let record = &buf[offset..];
        let next = u32::from_ne_bytes(record[0..4].try_into().unwrap());
        let version = [
            u32::from_ne_bytes(record[4..8].try_into().unwrap()),
            u32::from_ne_bytes(record[8..12].try_into().unwrap()),
            u32::from_ne_bytes(record[12..16].try_into().unwrap()),
        ];
        let name_bytes = &buf[name_start..end.max(name_start)];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        out.push(TargetVersion {
            name: String::from_utf8_lossy(&name_bytes[..nul]).into_owned(),
            version,
        });

        if next == 0 {
            return out;
        }
        offset = offset.saturating_add(next as usize);
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
        let device = Device::new(DevId::from_dev_t(dev), Arc::clone(&self.control));

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
    fn parse_versions_reads_a_single_record() {
        let buf = synthetic_versions_response(&[("linear", [1, 4, 0])]);
        assert_eq!(
            parse_versions(&buf),
            [TargetVersion {
                name: "linear".to_string(),
                version: [1, 4, 0],
            }]
        );
    }

    #[test]
    fn parse_versions_follows_next_relative_to_current_record() {
        let buf = synthetic_versions_response(&[
            ("linear", [1, 4, 0]),
            ("striped", [1, 6, 0]),
            ("thin-pool", [1, 23, 0]),
        ]);
        let got: Vec<(String, [u32; 3])> = parse_versions(&buf)
            .into_iter()
            .map(|t| (t.name, t.version))
            .collect();
        assert_eq!(
            got,
            [
                ("linear".to_string(), [1, 4, 0]),
                ("striped".to_string(), [1, 6, 0]),
                ("thin-pool".to_string(), [1, 23, 0]),
            ]
        );
    }

    #[test]
    fn parse_versions_yields_nothing_for_an_empty_list() {
        assert_eq!(parse_versions(&synthetic_versions_response(&[])), []);
    }

    #[test]
    fn parse_versions_stops_on_a_truncated_final_record() {
        // `data_size` claims a record the buffer doesn't actually hold: the
        // 16-byte-header guard must stop rather than slice out of bounds.
        let mut buf = vec![0u8; DmHeader::SIZE + 8];
        #[allow(clippy::cast_possible_truncation)]
        {
            buf[16..20].copy_from_slice(&(DmHeader::SIZE as u32).to_ne_bytes());
            buf[12..16].copy_from_slice(&((DmHeader::SIZE + 100) as u32).to_ne_bytes());
        }
        assert_eq!(parse_versions(&buf), []);
    }

    #[test]
    fn list_devices_iter_parses_single_entry() {
        let (buf, start, end) =
            synthetic_list_devices_response(&[(DevId::new(252, 5).unwrap().to_dev_t(), "foo")]);
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
            (DevId::new(252, 5).unwrap().to_dev_t(), "first"),
            (DevId::new(252, 6).unwrap().to_dev_t(), "second-longer-name"),
            (DevId::new(252, 7).unwrap().to_dev_t(), "third"),
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
