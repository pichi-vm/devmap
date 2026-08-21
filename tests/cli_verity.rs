// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `verity` persona: format a hash tree
//! over a loop-backed data device, then open, read back, verify, and
//! close it through the built binary (and its `veritysetup` symlink).
//!
//! Skips cleanly when device-mapper can't be opened (not root).

mod common;

use std::os::unix::fs::symlink;

use common::{BIN, LoopDevice, have_dm, run};

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
    let data = LoopDevice::filled("verity-data", 256 * 1024, &pattern);
    let hash = LoopDevice::sparse("verity-hash", 256 * 1024);

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
