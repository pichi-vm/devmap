// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `dm` persona: drive the built binary
//! (and its `dmsetup` symlink) against the live kernel.
//!
//! Skips cleanly when the device-mapper control node can't be opened
//! (i.e. not run as root), so `cargo test` stays green for unprivileged
//! builds; run the binary under `sudo -n` to exercise it.

use std::io::Write as _;
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};

use devmap_linux::Control;

/// Path to the freshly-built `devmap` binary, provided by cargo.
const BIN: &str = env!("CARGO_BIN_EXE_devmap");

/// True when we can talk to device-mapper (proxy for "running as root").
fn have_dm() -> bool {
    Control::open().is_ok()
}

/// Run `devmap <args...>` feeding `stdin`, returning (success, stdout).
fn run(argv0: &str, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(argv0)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn devmap");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait devmap");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn dm_persona_full_lifecycle() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }

    let name = format!("devmap-it-{}", std::process::id());
    let table = "0 8192 zero\n";

    // create from a table on stdin.
    let (ok, _) = run(BIN, &["dm", "create", &name], table);
    assert!(ok, "create should succeed");

    // ls lists it with a dev_t.
    let (ok, out) = run(BIN, &["dm", "ls"], "");
    assert!(ok && out.contains(&name), "ls should show {name}: {out}");

    // table reads back what we loaded.
    let (ok, out) = run(BIN, &["dm", "table", &name], "");
    assert!(ok && out.contains("0 8192 zero"), "table: {out}");

    // info reports an ACTIVE device with one target.
    let (ok, out) = run(BIN, &["dm", "info", &name], "");
    assert!(
        ok && out.contains("State:             ACTIVE") && out.contains("Number of targets: 1"),
        "info: {out}"
    );

    // The dmsetup symlink dispatches the same operation via argv[0]. The
    // basename must be exactly `dmsetup` for the multicall shim to match,
    // so isolate it in a per-run temp directory rather than suffixing.
    let link_dir = std::env::temp_dir().join(format!("devmap-it-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&link_dir);
    std::fs::create_dir_all(&link_dir).expect("mkdir link dir");
    let link = link_dir.join("dmsetup");
    symlink(BIN, &link).expect("symlink dmsetup");
    let (ok, out) = run(&link.to_string_lossy(), &["ls"], "");
    assert!(ok && out.contains(&name), "dmsetup ls: {out}");
    std::fs::remove_dir_all(&link_dir).ok();

    // remove tears it down.
    let (ok, _) = run(BIN, &["dm", "remove", &name], "");
    assert!(ok, "remove should succeed");

    let (_, out) = run(BIN, &["dm", "ls"], "");
    assert!(
        !out.contains(&name),
        "device should be gone after remove: {out}"
    );
}
