// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `zoned` persona: format a null_blk
//! zoned device, then check/start/status/stop it through the built
//! binary (and its `dmzadm` symlink translator).
//!
//! Skips cleanly when device-mapper can't be opened (not root) or the
//! environment can't provide a null_blk zoned device.

// Bare tool/device names (null_blk, dmzadm) read fine unquoted here.
#![allow(clippy::doc_markdown)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

use devmap_linux::Control;

/// Path to the freshly-built `devmap` binary, provided by cargo.
const BIN: &str = env!("CARGO_BIN_EXE_devmap");

fn have_dm() -> bool {
    Control::open().is_ok()
}

/// A memory-backed null_blk zoned device via configfs, torn down on drop.
struct NullBlkZoned {
    name: String,
    path: PathBuf,
}

impl NullBlkZoned {
    fn create() -> Option<Self> {
        let _ = Command::new("modprobe")
            .args(["null_blk", "nr_devices=0"])
            .status();
        let _ = Command::new("modprobe").arg("dm-zoned").status();
        let root = std::path::Path::new("/sys/kernel/config/nullb");
        if !root.exists() {
            return None;
        }
        let name = format!("devmapzt{}", std::process::id());
        let dir = root.join(&name);
        if fs::create_dir(&dir).is_err() {
            return None;
        }
        // 256 MiB, 4 MiB zones, 8 conventional zones.
        let set = |attr: &str, val: &str| fs::write(dir.join(attr), val);
        let built = set("memory_backed", "1")
            .and(set("zone_size", "4"))
            .and(set("zone_nr_conv", "8"))
            .and(set("zoned", "1"))
            .and(set("size", "256"))
            .and(set("power", "1"));
        let path = PathBuf::from(format!("/dev/{name}"));
        if built.is_err() || !path.exists() {
            let _ = fs::write(dir.join("power"), "0");
            let _ = fs::remove_dir(&dir);
            return None;
        }
        Some(NullBlkZoned { name, path })
    }

    fn dev(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for NullBlkZoned {
    fn drop(&mut self) {
        let dir = PathBuf::from("/sys/kernel/config/nullb").join(&self.name);
        let _ = fs::write(dir.join("power"), "0");
        let _ = fs::remove_dir(&dir);
    }
}

/// Run `argv0 args...`, returning (success, stdout).
fn run(argv0: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(argv0)
        .args(args)
        .output()
        .expect("spawn devmap");
    if !out.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn zoned_persona_format_start_status() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }
    let Some(nb) = NullBlkZoned::create() else {
        eprintln!("skipping: could not create a null_blk zoned device");
        return;
    };
    let dev = nb.dev();

    // format writes the metadata.
    let (ok, out) = run(BIN, &["zoned", "format", &dev, "--label", "cli-test"]);
    assert!(ok, "format should succeed");
    assert!(
        out.contains("Data chunks:"),
        "format prints a layout: {out}"
    );

    // check validates the superblock we wrote.
    let (ok, out) = run(BIN, &["zoned", "check", &dev]);
    assert!(ok && out.contains("is valid"), "check: {out}");

    // The dmzadm symlink translates --start into `zoned start`.
    let link_dir = std::env::temp_dir().join(format!("devmap-zt-link-{}", std::process::id()));
    let _ = fs::remove_dir_all(&link_dir);
    fs::create_dir_all(&link_dir).expect("mkdir link dir");
    let link = link_dir.join("dmzadm");
    symlink(BIN, &link).expect("symlink dmzadm");
    let name = format!("devmap-zt-{}", std::process::id());
    let (ok, _) = run(&link.to_string_lossy(), &["--start", &dev, &name]);
    assert!(ok, "dmzadm --start should activate the device");
    fs::remove_dir_all(&link_dir).ok();

    // status parses as zoned::Info and reports every zone.
    let (ok, out) = run(BIN, &["zoned", "status", &name]);
    assert!(ok && out.contains("zones"), "status: {out}");

    // Read/write through the mapped device to prove it is live.
    let node = format!("/dev/mapper/{name}");
    let mut ready = false;
    for _ in 0..50 {
        if fs::metadata(&node).is_ok() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(ready, "mapped device node should appear");
    let pattern = vec![0x5au8; 4096];
    fs::write(&node, &pattern).expect("write through dm-zoned");
    let readback = fs::read(&node).expect("read dm-zoned");
    assert_eq!(&readback[..4096], &pattern[..], "dm-zoned serves the data");

    // stop tears it down.
    let (ok, _) = run(BIN, &["zoned", "stop", &name]);
    assert!(ok, "stop should succeed");
}
