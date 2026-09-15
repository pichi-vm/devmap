// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for real-kernel integration tests: a root-gated
//! `Control::open()` skip check, and a sparse-file-backed loop device for
//! tests that need a real (if tiny) block device without touching real
//! hardware.
//!
//! Every test binary that `mod common;`s this file compiles the whole
//! thing but typically uses only part of it (e.g. `zoned_target.rs`
//! doesn't need `LoopDevice`) — `#![allow(dead_code)]` avoids per-binary
//! false-positive dead-code warnings from that, not from genuinely
//! unused code.
#![allow(dead_code)]

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use devmap_linux::{Control, Device};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Returns `None` (and prints a skip notice) if this process can't open
/// `/dev/mapper/control` — i.e. isn't root / doesn't have `CAP_SYS_ADMIN`.
pub(crate) fn open_control() -> Option<Control> {
    if let Ok(control) = Control::open() {
        return Some(control);
    }
    eprintln!("skip: requires root (or CAP_SYS_ADMIN) for /dev/mapper/control");
    None
}

/// A dm device that this test owns, torn down when the test's scope ends.
///
/// The library deliberately has no `Drop`-based removal: a dm device is
/// kernel state that outlives the process, so deciding when it dies belongs
/// to the caller. A test *is* that caller, and what it wants is
/// scope-bounded cleanup that still happens when an assertion panics — so
/// the guard lives here, in the harness, rather than in the API every real
/// user has to work around.
///
/// Removal is deferred: a device a test still has open (or that udev is
/// mid-scan on) is reclaimed by the kernel once released, instead of
/// leaking on `EBUSY`. Errors are swallowed because a cleanup failure
/// during unwind must not mask the assertion that actually failed; call
/// [`Owned::remove`] where the removal itself is what's under test.
pub(crate) struct Owned(Option<Device>);

impl Owned {
    /// `DM_DEV_CREATE` a device this scope owns.
    pub(crate) fn create(control: &Control, name: &str) -> io::Result<Self> {
        control.create(name).map(|d| Self(Some(d)))
    }

    /// Remove it now, surfacing the kernel's error, and disarm the guard.
    pub(crate) fn remove(mut self) -> io::Result<()> {
        self.0.take().expect("armed").remove()
    }

    /// Give up ownership: the device outlives this scope.
    pub(crate) fn leak(mut self) -> Device {
        self.0.take().expect("armed")
    }
}

impl std::ops::Deref for Owned {
    type Target = Device;
    fn deref(&self) -> &Device {
        self.0.as_ref().expect("armed")
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(device) = self.0.take() {
            let _ = device.remove_deferred();
        }
    }
}

/// A sparse backing file attached as a loop device via `losetup`. Detaches
/// the loop device and deletes the backing file on drop (best-effort).
pub(crate) struct LoopDevice {
    pub(crate) path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    /// Creates a `size_bytes`-sized sparse file and attaches it.
    pub(crate) fn create(name: &str, size_bytes: u64) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let file_path =
            std::env::temp_dir().join(format!("devmap-test-{name}-{}-{id}", std::process::id()));
        let file = File::create(&file_path).expect("create backing file");
        file.set_len(size_bytes).expect("set_len backing file");
        drop(file);

        let output = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&file_path)
            .output()
            .expect("run losetup -f --show");
        assert!(
            output.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = String::from_utf8(output.stdout)
            .expect("losetup output is utf8")
            .trim()
            .to_string();

        Self { path, file_path }
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.path]).status();
        let _ = std::fs::remove_file(&self.file_path);
    }
}

/// Best-effort `modprobe` for a dm target's kernel module. Most targets
/// auto-load via `request_module` when first referenced in a table, but
/// this makes failures easier to diagnose than a bare `ENOENT`/`EINVAL`
/// from `DM_TABLE_LOAD`. Ignored if it fails (e.g. already built in).
pub(crate) fn ensure_module_loaded(name: &str) {
    let _ = Command::new("modprobe").arg("-q").arg(name).status();
}
