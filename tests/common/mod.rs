// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the CLI's root integration tests: the path to the
//! built binary, the root-gated skip check, a command runner, and a
//! loop-backed block device.
//!
//! Every test binary that `mod common;`s this file compiles all of it but
//! uses only part (`cli_dm.rs` needs no loop device) — `#![allow(dead_code)]`
//! suppresses the per-binary false positives that causes, not warnings
//! about genuinely unused code.
#![allow(dead_code)]

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use devmap_linux::Control;

/// Path to the freshly-built `devmap` binary, provided by cargo.
pub(crate) const BIN: &str = env!("CARGO_BIN_EXE_devmap");

/// Distinguishes backing files within one test binary, which runs its
/// tests concurrently under a single pid.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Whether this process can drive device-mapper at all, i.e. is root or
/// holds `CAP_SYS_ADMIN`. Tests skip rather than fail without it.
pub(crate) fn have_dm() -> bool {
    Control::open().is_ok()
}

/// Run `argv0 args…`, returning (success, stdout). A failing command has
/// its stderr echoed, so a broken assertion downstream comes with the
/// reason attached.
pub(crate) fn run(argv0: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(argv0)
        .args(args)
        .output()
        .expect("spawn the command");
    if !out.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// As [`run`], but returning stderr instead of echoing it — for the tests
/// whose subject is a diagnostic rather than a result.
pub(crate) fn run_capturing(argv0: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(argv0)
        .args(args)
        .output()
        .expect("spawn the command");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A backing file attached as a loop device, giving a test a real block
/// device without touching real hardware. Detaches and deletes the
/// backing file on drop, best-effort.
pub(crate) struct LoopDevice {
    /// The `/dev/loopN` path the kernel handed out.
    pub(crate) path: String,
    /// The file behind it — readable directly to inspect what a mapping
    /// actually wrote.
    pub(crate) file_path: PathBuf,
}

impl LoopDevice {
    /// Attach an existing file. The caller owns its contents; this only
    /// takes over detaching and deleting it.
    pub(crate) fn attach(file_path: PathBuf) -> Self {
        let out = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&file_path)
            .output()
            .expect("run losetup -f --show");
        assert!(
            out.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = String::from_utf8(out.stdout)
            .expect("losetup output is utf8")
            .trim()
            .to_string();
        Self { path, file_path }
    }

    /// Attach a `size`-byte sparse file. `tag` names it, so the temp
    /// directory says which test left something behind.
    pub(crate) fn sparse(tag: &str, size: u64) -> Self {
        let file_path = backing_path(tag);
        File::create(&file_path)
            .and_then(|f| f.set_len(size))
            .expect("create the backing file");
        Self::attach(file_path)
    }

    /// Attach a `size`-byte file filled by repeating `pattern`, for tests
    /// that read data back and compare it.
    pub(crate) fn filled(tag: &str, size: u64, pattern: &[u8]) -> Self {
        let file_path = backing_path(tag);
        let mut handle = File::create(&file_path).expect("create the backing file");
        let mut written = 0u64;
        while written < size {
            let remaining = usize::try_from(size - written).unwrap_or(usize::MAX);
            let n = remaining.min(pattern.len());
            handle
                .write_all(&pattern[..n])
                .expect("fill the backing file");
            written += n as u64;
        }
        handle.sync_all().ok();
        drop(handle);
        Self::attach(file_path)
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.path]).status();
        let _ = std::fs::remove_file(&self.file_path);
    }
}

/// A collision-free temp path for a backing file.
fn backing_path(tag: &str) -> PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("devmap-cli-{tag}-{}-{id}", std::process::id()))
}
