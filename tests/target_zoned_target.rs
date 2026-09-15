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

#[path = "support/dm.rs"]
mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

use common::{Owned, ensure_module_loaded, open_control};
use devmap_zoned::dm::Target as Zoned;

/// Whether `name` resolves on `$PATH`. Used to skip if `dmzadm` isn't
/// installed, the same way `common::open_control` skips for missing root.
fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A private configfs `null_blk` device; never unloads the shared module.
struct NullBlkZonedDevice {
    path: String,
    directory: std::path::PathBuf,
}
impl NullBlkZonedDevice {
    fn create(zone_size_mb: u32, zone_nr_conv: u32, gb: u32) -> Option<Self> {
        let _ = Command::new("modprobe")
            .args(["null_blk", "nr_devices=0"])
            .status();
        let root = std::path::Path::new("/sys/kernel/config/nullb");
        if !root.is_dir() {
            eprintln!("skip: null_blk configfs unavailable");
            return None;
        }
        let name = format!("devmapzonedtarget{}", std::process::id());
        let directory = root.join(&name);
        std::fs::create_dir(&directory).ok()?;
        let device = Self {
            path: format!("/dev/{name}"),
            directory,
        };
        for (attribute, value) in [
            ("memory_backed", "1".into()),
            ("zone_size", zone_size_mb.to_string()),
            ("zone_nr_conv", zone_nr_conv.to_string()),
            ("zoned", "1".into()),
            ("size", (u64::from(gb) * 1024).to_string()),
            ("power", "1".into()),
        ] {
            if std::fs::write(device.directory.join(attribute), value).is_err() {
                return None;
            }
        }
        if !std::path::Path::new(&device.path).exists() {
            return None;
        }
        Some(device)
    }
}
impl Drop for NullBlkZonedDevice {
    fn drop(&mut self) {
        let _ = std::fs::write(self.directory.join("power"), "0");
        let _ = std::fs::remove_dir(&self.directory);
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
        .arg(&zoned.path)
        .output()
        .expect("run dmzadm --format");
    assert!(
        format.status.success(),
        "dmzadm --format failed: {}",
        String::from_utf8_lossy(&format.stderr)
    );

    let zoned_device = control.by_node(&zoned.path).expect("by_node zoned device");

    // dm-zoned's usable size is smaller than the raw device (some zones
    // are reserved for metadata/reclaim) and that reservation isn't
    // something devmap computes — `dmzadm --start` already knows it, so
    // ask it once via a throwaway device rather than guessing. `dmzadm`
    // names the device `dmz-<basename>` (e.g. `dmz-nullb0`).
    let start = Command::new("dmzadm")
        .arg("--start")
        .arg(&zoned.path)
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
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
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
    dev.resume().expect("resume");

    let mut file = dev.open_rw().expect("open");
    let pattern = [0x5Eu8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);

    let status: Vec<_> = dev.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].type_name(), "zoned");
}
