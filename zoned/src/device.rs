// SPDX-License-Identifier: Apache-2.0

//! The Linux-coupled half of the crate: querying zone geometry off a real
//! device with `BLKREPORTZONE`, and writing a formatted metadata region to
//! it.
//!
//! This is the only module that issues syscalls, so it is the only place
//! that reaches for `unsafe` — the two ioctls the portable format code
//! cannot express.

#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use crate::{BLOCK_SIZE, FormatOptions, Geometry, Layout};

/// `_IOC(dir, type, nr, size)` from `<asm-generic/ioctl.h>`.
const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
}

// From `<linux/blkzoned.h>` / `<linux/fs.h>`. BLKGETNRZONES reads a u32
// zone count; BLKREPORTZONE fills a caller-sized buffer of zone records.
const BLKGETNRZONES: libc::c_ulong = ioc(2, 0x12, 133, 4);
const BLKREPORTZONE: libc::c_ulong = ioc(3, 0x12, 130, BLK_ZONE_REPORT_HEADER as u32);

/// `struct blk_zone_report`: `__u64 sector; __u32 nr_zones; __u32 flags;`
/// then the zone array.
const BLK_ZONE_REPORT_HEADER: usize = 16;
/// `struct blk_zone` is 64 bytes; `len` (u64) is at +8 and `type` (u8) at
/// +24.
const BLK_ZONE_SIZE: usize = 64;
const BLK_ZONE_OFF_LEN: usize = 8;
const BLK_ZONE_OFF_TYPE: usize = 24;
/// `BLK_ZONE_TYPE_CONVENTIONAL` — a randomly-writable zone.
const ZONE_TYPE_CONVENTIONAL: u8 = 1;
/// dm-zoned blocks are 4096 bytes; the report reports lengths in 512-byte
/// sectors.
const SECTORS_PER_BLOCK: u64 = (BLOCK_SIZE / 512) as u64;

/// Read the zone [`Geometry`] of the block device at `path`.
///
/// Uses `BLKGETNRZONES` for the zone count and `BLKREPORTZONE` for the
/// per-zone type and size. `conventional_zones` counts the leading run of
/// conventional zones, which is where dm-zoned places its metadata.
///
/// # Errors
///
/// The underlying `io::Error` if `path` can't be opened, either ioctl
/// fails (`ENOTTY`/`EINVAL` on a non-zoned device), or the report is
/// empty.
pub fn report_zones(path: impl AsRef<Path>) -> io::Result<Geometry> {
    let file = OpenOptions::new().read(true).open(path)?;
    let fd = file.as_raw_fd();

    let mut nr_zones: u32 = 0;
    // SAFETY: BLKGETNRZONES writes a u32 through the pointer; nr_zones is a
    // live u32 for the duration of the call.
    if unsafe { libc::ioctl(fd, BLKGETNRZONES, &raw mut nr_zones) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if nr_zones == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "device reports zero zones (not a zoned device?)",
        ));
    }

    let mut buf = vec![0u8; BLK_ZONE_REPORT_HEADER + nr_zones as usize * BLK_ZONE_SIZE];
    // sector = 0 (report from the start); nr_zones = capacity.
    buf[8..12].copy_from_slice(&nr_zones.to_le_bytes());
    // SAFETY: BLKREPORTZONE reads the 16-byte header and writes up to
    // nr_zones records into the buffer, which is sized exactly for that.
    if unsafe { libc::ioctl(fd, BLKREPORTZONE, buf.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let reported = u32::from_le_bytes(buf[8..12].try_into().unwrap());

    let zone = |i: usize| &buf[BLK_ZONE_REPORT_HEADER + i * BLK_ZONE_SIZE..];
    let first = zone(0);
    let zone_len_sectors = u64::from_le_bytes(
        first[BLK_ZONE_OFF_LEN..BLK_ZONE_OFF_LEN + 8]
            .try_into()
            .unwrap(),
    );
    let zone_size_blocks = u32::try_from(zone_len_sectors / SECTORS_PER_BLOCK)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "zone too large"))?;

    let conventional_zones = (0..reported as usize)
        .take_while(|&i| zone(i)[BLK_ZONE_OFF_TYPE] == ZONE_TYPE_CONVENTIONAL)
        .count() as u32;

    Ok(Geometry {
        total_zones: nr_zones,
        zone_size_blocks,
        conventional_zones,
    })
}

/// Format the zoned block device at `path` for dm-zoned, with no external
/// tool, and return the [`Layout`] that was written.
///
/// Queries the geometry, computes the layout, and writes both the primary
/// and secondary metadata sets. Afterward the device is ready for a
/// `zoned` table load (see `devmap-linux`).
///
/// # Errors
///
/// [`FormatError`] wrapping either the geometry/layout failure or the
/// underlying I/O error.
pub fn format(path: impl AsRef<Path>, options: &FormatOptions) -> Result<Layout, FormatError> {
    // The kernel rejects a null volume or device UUID outright, so catch
    // it here with a clear error rather than a cryptic EIO at table load.
    if options.dmz_uuid == [0u8; 16] || options.dev_uuid == [0u8; 16] {
        return Err(FormatError::NullUuid);
    }
    let path = path.as_ref();
    let geometry = report_zones(path).map_err(FormatError::Io)?;
    let layout = Layout::compute(geometry, options).map_err(FormatError::Layout)?;

    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(FormatError::Io)?;
    for set in 0..2 {
        let region = layout.metadata_set(set, options);
        let offset = layout.set_start_block(set) * BLOCK_SIZE as u64;
        file.write_all_at(&region, offset)
            .map_err(FormatError::Io)?;
    }
    file.sync_all().map_err(FormatError::Io)?;
    Ok(layout)
}

/// Why [`format`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum FormatError {
    /// A required UUID in [`FormatOptions`] was all zero; the kernel would
    /// reject the resulting volume.
    NullUuid,
    /// The geometry couldn't host a dm-zoned volume.
    Layout(crate::LayoutError),
    /// A device query or write failed.
    Io(io::Error),
}

impl core::fmt::Display for FormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FormatError::NullUuid => {
                f.write_str("dm-zoned format: dmz_uuid and dev_uuid must be non-zero")
            }
            FormatError::Layout(e) => write!(f, "dm-zoned layout: {e}"),
            FormatError::Io(e) => write!(f, "dm-zoned format I/O: {e}"),
        }
    }
}

impl core::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FormatError::NullUuid => None,
            FormatError::Layout(e) => Some(e),
            FormatError::Io(e) => Some(e),
        }
    }
}
