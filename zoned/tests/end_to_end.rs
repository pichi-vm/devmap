// SPDX-License-Identifier: Apache-2.0

//! The whole point of the crate, end to end: format a real zoned device
//! with pure Rust, then have the kernel activate dm-zoned over it — no
//! dmzadm anywhere. If the kernel accepts the metadata and the mapped
//! device serves I/O, the format is correct.
//!
//! Requires root (for `/dev/mapper/control`, configfs, and the module
//! loads) and null_blk with zoned support; skips otherwise.

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::PathBuf;

use devmap_linux::Control;
use devmap_linux::targets::Zoned;
use devmap_zoned::FormatOptions;

/// A memory-backed null_blk zoned device, created via configfs and torn
/// down on drop. `None` if the environment can't provide one.
struct NullBlkZoned {
    name: String,
    path: PathBuf,
}

impl NullBlkZoned {
    fn create() -> Option<Self> {
        // Root and the module are prerequisites; a plain modprobe attempt
        // that fails means we skip rather than fail.
        let _ = std::process::Command::new("modprobe")
            .arg("null_blk")
            .arg("nr_devices=0")
            .status();
        let root = std::path::Path::new("/sys/kernel/config/nullb");
        if !root.exists() {
            return None;
        }
        let name = format!("devmapzoned{}", std::process::id());
        let dir = root.join(&name);
        if fs::create_dir(&dir).is_err() {
            return None;
        }
        // 256 MiB, 4 MiB zones, 8 conventional zones — enough for two
        // metadata sets plus data zones.
        let set = |attr: &str, val: &str| fs::write(dir.join(attr), val);
        let built = set("memory_backed", "1")
            .and(set("zone_size", "4"))
            .and(set("zone_nr_conv", "8"))
            .and(set("zoned", "1"))
            .and(set("size", "256"))
            .and(set("power", "1"));
        if built.is_err() {
            let _ = fs::write(dir.join("power"), "0");
            let _ = fs::remove_dir(&dir);
            return None;
        }
        let path = PathBuf::from(format!("/dev/{name}"));
        if !path.exists() {
            let _ = fs::write(dir.join("power"), "0");
            let _ = fs::remove_dir(&dir);
            return None;
        }
        Some(NullBlkZoned { name, path })
    }
}

impl Drop for NullBlkZoned {
    fn drop(&mut self) {
        let dir = PathBuf::from("/sys/kernel/config/nullb").join(&self.name);
        let _ = fs::write(dir.join("power"), "0");
        let _ = fs::remove_dir(&dir);
    }
}

#[test]
fn format_then_activate_dm_zoned_and_serve_io() {
    let Ok(control) = Control::open() else {
        eprintln!("skip: requires root for /dev/mapper/control");
        return;
    };
    let Some(dev) = NullBlkZoned::create() else {
        eprintln!("skip: could not create a null_blk zoned device");
        return;
    };
    let _ = std::process::Command::new("modprobe")
        .arg("dm-zoned")
        .status();

    // Format with pure Rust — this is the dmzadm replacement under test.
    // The kernel requires non-zero UUIDs, which a caller supplies.
    let options = FormatOptions {
        label: *b"devmap-zoned-test\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        dmz_uuid: [0x11; 16],
        dev_uuid: [0x22; 16],
        reserved_seq: None,
    };
    let layout = devmap_zoned::format(&dev.path, &options).expect("format the zoned device");
    assert!(layout.nr_chunks() > 0);

    // Re-read the primary superblock straight off the device and confirm
    // it parses and round-trips — the bytes we wrote are what the kernel
    // will read.
    let mut block = [0u8; devmap_zoned::BLOCK_SIZE];
    OpenOptions::new()
        .read(true)
        .open(&dev.path)
        .and_then(|mut f| f.read_exact(&mut block))
        .expect("read back superblock");
    let sb = devmap_zoned::Superblock::from_block(&block).expect("our superblock must parse");
    assert_eq!(sb.nr_chunks, layout.nr_chunks());

    // The real test: the kernel accepts the metadata and activates
    // dm-zoned over it.
    let zoned_dev = control.by_node(&dev.path).expect("by_node zoned");
    let name = format!("devmap-test-zoned-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            layout.logical_sectors(),
            Zoned {
                device: zoned_dev.id(),
            },
        )
        .expect("add zoned target")
        .load()
        .expect("DM_TABLE_LOAD — the kernel must accept our metadata");
    removed.resume().expect("resume dm-zoned");

    // Its status parses as zoned::Info and reports the zones we formatted.
    let info: Vec<_> = removed.info().expect("dm-zoned info").collect();
    assert_eq!(info.len(), 1);
    let status = info[0]
        .parse::<Zoned>()
        .expect("dm-zoned info must parse as zoned::Info");
    assert_eq!(
        status.total_zones,
        layout.geometry().total_zones,
        "status must report every zone we formatted"
    );

    // Serve real I/O through the mapped device to prove it is live.
    let minor = removed.id().minor();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{minor}"))
        .expect("open mapped dm-zoned device");
    let pattern = [0x5au8; 4096];
    file.write_all(&pattern).expect("write through dm-zoned");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern, "dm-zoned must serve the data written");
}
