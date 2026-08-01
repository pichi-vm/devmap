// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `dm-zoned`, using a `null_blk`-emulated
//! host-managed zoned block device instead of real ZBC/ZAC hardware.
//!
//! Unlike every other target in this crate, `dm-zoned` requires its
//! backing device to already carry valid on-disk metadata — the kernel
//! target has no self-formatting fallback (confirmed against
//! `dm-zoned-metadata.c`: an all-zero superblock is rejected outright,
//! unlike `dm-integrity`'s "format on first load" behavior). That
//! metadata is written by the external `dmzadm` tool (packaged as
//! `dm-zoned-tools`), so this test skips gracefully if it isn't
//! installed, the same way other tests skip for missing root.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

use common::{ensure_module_loaded, open_control};
use devmap::targets::Zoned;

/// Whether `name` resolves on `$PATH`. Used to skip if `dmzadm` isn't
/// installed, the same way `common::open_control` skips for missing root.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A `null_blk`-emulated host-managed zoned block device (`/dev/nullb0`),
/// for exercising `dm-zoned` without real ZBC/ZAC hardware. `null_blk`
/// only supports one global module instance at a time — fine here since
/// this is the only test using it, and real-kernel integration binaries
/// in this crate already run single-threaded (`--test-threads=1`).
///
/// Returns `None` (and prints a skip notice) if `null_blk` can't be
/// loaded in zoned mode — e.g. a kernel built without
/// `CONFIG_BLK_DEV_NULL_BLK` zoned support.
struct NullBlkZonedDevice {
    path: &'static str,
}

impl NullBlkZonedDevice {
    /// `zone_size_mb` must be a power of two; `gb` must be a multiple of it.
    fn create(zone_size_mb: u32, zone_nr_conv: u32, gb: u32) -> Option<Self> {
        let _ = Command::new("modprobe")
            .args(["-q", "-r", "null_blk"])
            .status();
        let status = Command::new("modprobe")
            .arg("null_blk")
            .arg("nr_devices=1")
            .arg("zoned=1")
            .arg("memory_backed=1")
            .arg(format!("zone_size={zone_size_mb}"))
            .arg(format!("zone_nr_conv={zone_nr_conv}"))
            .arg(format!("gb={gb}"))
            .status();
        if !status.is_ok_and(|s| s.success()) || !std::path::Path::new("/dev/nullb0").exists() {
            eprintln!("skip: null_blk zoned emulation unavailable on this kernel");
            return None;
        }
        Some(Self {
            path: "/dev/nullb0",
        })
    }
}

impl Drop for NullBlkZonedDevice {
    fn drop(&mut self) {
        let _ = Command::new("modprobe")
            .args(["-q", "-r", "null_blk"])
            .status();
    }
}

#[test]
fn zoned_formats_with_dmzadm_and_passes_data_through() {
    let Some(control) = open_control() else {
        return;
    };
    if !command_exists("dmzadm") {
        eprintln!("skip: requires the dmzadm tool (package: dm-zoned-tools)");
        return;
    }
    ensure_module_loaded("dm-zoned");

    let Some(zoned) = NullBlkZonedDevice::create(4, 8, 1) else {
        return;
    };

    let format = Command::new("dmzadm")
        .arg("--format")
        .arg(zoned.path)
        .output()
        .expect("run dmzadm --format");
    assert!(
        format.status.success(),
        "dmzadm --format failed: {}",
        String::from_utf8_lossy(&format.stderr)
    );

    let zoned_device = control.by_node(zoned.path).expect("by_node zoned device");

    // dm-zoned's usable size is smaller than the raw device (some zones
    // are reserved for metadata/reclaim) and that reservation isn't
    // something devmap computes — `dmzadm --start` already knows it, so
    // ask it once via a throwaway device rather than guessing. `dmzadm`
    // names the device `dmz-<basename>` (e.g. `dmz-nullb0`).
    let start = Command::new("dmzadm")
        .arg("--start")
        .arg(zoned.path)
        .output()
        .expect("run dmzadm --start");
    assert!(
        start.status.success(),
        "dmzadm --start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    let dm_name = format!("dmz-{}", zoned.path.trim_start_matches("/dev/"));
    let table_output = Command::new("dmsetup")
        .args(["table", &dm_name])
        .output()
        .expect("dmsetup table");
    let table_line = String::from_utf8_lossy(&table_output.stdout)
        .trim()
        .to_string();
    let usable_sectors: u64 = table_line
        .split_whitespace()
        .nth(1)
        .expect("table line has a length field")
        .parse()
        .expect("parse length");
    Command::new("dmsetup")
        .args(["remove", &dm_name])
        .status()
        .expect("dmsetup remove probe device");

    let name = format!("devmap-test-zoned-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            usable_sectors,
            Zoned {
                device: zoned_device.id(),
            },
        )
        .expect("add zoned")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{minor}"))
        .expect("open");
    let pattern = [0x5Eu8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);

    let status: Vec<_> = removed.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].type_name(), "zoned");
}
