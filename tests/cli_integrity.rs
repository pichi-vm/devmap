// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `integrity` persona: format a loop
//! device, open it, and round-trip data through the mapping via the
//! built binary (and its `integritysetup` symlink).
//!
//! Skips cleanly when device-mapper can't be opened (not root).
//!
//! Reads back only the region it wrote: a freshly formatted
//! dm-integrity device has uninitialised tags elsewhere (there is no
//! whole-device wipe pass), so reading unwritten blocks would fail an
//! integrity check — expected, not a persona bug.

use std::fs::File;
use std::os::unix::fs::{FileExt as _, symlink};
use std::path::PathBuf;
use std::process::Command;

use devmap_linux::Control;

/// Path to the freshly-built `devmap` binary, provided by cargo.
const BIN: &str = env!("CARGO_BIN_EXE_devmap");

fn have_dm() -> bool {
    Control::open().is_ok()
}

/// A sparse backing file attached as a loop device; detaches on drop.
struct LoopDevice {
    path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    fn create(size: u64) -> Self {
        let file_path =
            std::env::temp_dir().join(format!("devmap-it-integ-{}", std::process::id()));
        File::create(&file_path)
            .and_then(|f| f.set_len(size))
            .expect("create backing file");
        let out = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&file_path)
            .output()
            .expect("run losetup");
        assert!(
            out.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = String::from_utf8(out.stdout).unwrap().trim().to_string();
        Self { path, file_path }
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.path]).status();
        let _ = std::fs::remove_file(&self.file_path);
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
fn integrity_persona_format_open_roundtrip() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }
    let _ = Command::new("modprobe").arg("dm-integrity").status();

    let dev = LoopDevice::create(32 * 1024 * 1024);

    // format writes a superblock sized to the device.
    let (ok, out) = run(BIN, &["integrity", "format", &dev.path]);
    assert!(ok, "format should succeed");
    assert!(
        out.contains("Provided data sectors:"),
        "format prints capacity: {out}"
    );

    // The integritysetup symlink dispatches open the same way.
    let link_dir = std::env::temp_dir().join(format!("devmap-it-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&link_dir);
    std::fs::create_dir_all(&link_dir).expect("mkdir link dir");
    let link = link_dir.join("integritysetup");
    symlink(BIN, &link).expect("symlink integritysetup");
    let name = format!("devmap-it-integ-{}", std::process::id());
    let (ok, _) = run(&link.to_string_lossy(), &["open", &dev.path, &name]);
    assert!(ok, "integritysetup open should activate the device");
    std::fs::remove_dir_all(&link_dir).ok();

    // status parses as integrity::Info (mismatches, sectors, recalc).
    let (ok, out) = run(BIN, &["integrity", "status", &name]);
    assert!(ok && out.split_whitespace().count() == 3, "status: {out}");

    // Round-trip a block through the mapped device. Going through the
    // kernel's own node rather than the /dev/mapper symlink means there is
    // no udev arrival to wait for.
    let control = Control::open().expect("open the control device");
    let (mapped, _) = control.by_name(&name).expect("look the mapping up");
    let file = mapped.open_rw().expect("mapped integrity device opens");
    let pattern: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    file.write_all_at(&pattern, 0)
        .expect("write through integrity");
    file.sync_all().expect("sync");
    let mut readback = vec![0u8; pattern.len()];
    file.read_exact_at(&mut readback, 0)
        .expect("read the written region back");
    assert_eq!(
        readback, pattern,
        "integrity device serves the data written"
    );
    drop(file);

    // close tears it down.
    let (ok, _) = run(BIN, &["integrity", "close", &name]);
    assert!(ok, "close should succeed");
}
