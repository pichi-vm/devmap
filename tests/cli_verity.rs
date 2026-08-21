// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `verity` persona: format a hash tree
//! over a loop-backed data device, then open, read back, verify, and
//! close it through the built binary (and its `veritysetup` symlink).
//!
//! Skips cleanly when device-mapper can't be opened (not root).

use std::fs::File;
use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

use devmap_linux::Control;

/// Path to the freshly-built `devmap` binary, provided by cargo.
const BIN: &str = env!("CARGO_BIN_EXE_devmap");

fn have_dm() -> bool {
    Control::open().is_ok()
}

/// A sparse (or pre-filled) backing file attached as a loop device;
/// detaches and deletes on drop.
struct LoopDevice {
    path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    /// Attach a `size` byte file, optionally pre-filled with `fill`.
    fn create(tag: &str, size: u64, fill: Option<&[u8]>) -> Self {
        let backing = std::env::temp_dir().join(format!("devmap-vt-{tag}-{}", std::process::id()));
        let mut handle = File::create(&backing).expect("create backing file");
        if let Some(bytes) = fill {
            let mut written = 0u64;
            while written < size {
                let remaining = usize::try_from(size - written).unwrap_or(usize::MAX);
                let n = remaining.min(bytes.len());
                handle.write_all(&bytes[..n]).expect("fill backing file");
                written += n as u64;
            }
        } else {
            handle.set_len(size).expect("size backing file");
        }
        handle.sync_all().ok();
        drop(handle);

        let out = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&backing)
            .output()
            .expect("run losetup");
        assert!(
            out.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = String::from_utf8(out.stdout).unwrap().trim().to_string();
        Self {
            path,
            file_path: backing,
        }
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

/// Extract the `Root hash:` value from `verity format` output.
fn root_hash_of(format_output: &str) -> String {
    format_output
        .lines()
        .find(|l| l.contains("Root hash:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("format prints a root hash")
        .to_string()
}

#[test]
fn verity_persona_format_open_verify() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }

    // 256 KiB of a known byte pattern so we can compare a readback.
    let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let data = LoopDevice::create("data", 256 * 1024, Some(&pattern));
    let hash = LoopDevice::create("hash", 256 * 1024, None);

    // format, capturing the root hash.
    let (ok, out) = run(BIN, &["verity", "format", &data.path, &hash.path]);
    assert!(ok, "format should succeed");
    let root = root_hash_of(&out);
    assert_eq!(root.len(), 64, "sha256 root hash is 64 hex chars");

    // verify recomputes and matches.
    let (ok, out) = run(BIN, &["verity", "verify", &data.path, &hash.path, &root]);
    assert!(ok && out.contains("successful"), "verify: {out}");

    // A wrong root hash must fail verification.
    let bad = "0".repeat(64);
    let (ok, _) = run(BIN, &["verity", "verify", &data.path, &hash.path, &bad]);
    assert!(!ok, "verify with a bad root hash must fail");

    // open, then read the mapped device back and compare to the data.
    let name = format!("devmap-vt-{}", std::process::id());
    let (ok, _) = run(
        BIN,
        &["verity", "open", &data.path, &name, &hash.path, &root],
    );
    assert!(ok, "open should succeed");

    // Deliberately through /dev/mapper/<name> rather than the kernel's own
    // node: that symlink is the surface the CLI documents, so one test
    // holds it. udev creates it asynchronously, hence the poll — every
    // other test reaches the mapping via `Device::node_path`, which is
    // there the moment the table goes live.
    let node = format!("/dev/mapper/{name}");
    let mut mapped = None;
    for _ in 0..50 {
        match std::fs::read(&node) {
            Ok(bytes) if bytes.len() >= 4096 => {
                mapped = Some(bytes);
                break;
            }
            _ => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let mapped = mapped.expect("mapped verity device becomes readable");
    assert_eq!(
        &mapped[..4096],
        &pattern[..],
        "readback matches data device"
    );

    // The veritysetup symlink dispatches status the same way.
    let link_dir = std::env::temp_dir().join(format!("devmap-vt-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&link_dir);
    std::fs::create_dir_all(&link_dir).expect("mkdir link dir");
    let link = link_dir.join("veritysetup");
    symlink(BIN, &link).expect("symlink veritysetup");
    let (ok, out) = run(&link.to_string_lossy(), &["status", &name]);
    assert!(ok && out.contains("verified"), "veritysetup status: {out}");
    std::fs::remove_dir_all(&link_dir).ok();

    // close tears it down.
    let (ok, _) = run(BIN, &["verity", "close", &name]);
    assert!(ok, "close should succeed");
}
