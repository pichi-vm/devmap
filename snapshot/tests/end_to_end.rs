// SPDX-License-Identifier: Apache-2.0

//! The whole point of the crate, end to end: convert a raw image into a
//! persistent COW with pure Rust, then have the kernel activate
//! dm-snapshot over it (a zero origin + our COW) and serve the image back
//! — no lvcreate anywhere. If the kernel accepts the COW and the mapped
//! device reads back the original image, the format is correct.
//!
//! This is the kernel acceptance check pichi deferred. Requires root (for
//! `/dev/mapper/control` and losetup); skips otherwise.

#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::PathBuf;
use std::process::Command;

use devmap_linux::Control;
use devmap_linux::targets::{Snapshot, Zero};

/// Chunk size for the test COW: 8 sectors = 4 KiB (the kernel minimum).
const CHUNK_SIZE_SECTORS: u32 = 8;

/// A backing file attached as a loop device; detaches and deletes on drop.
struct LoopDevice {
    path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    fn attach(file_path: PathBuf) -> Self {
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

#[test]
fn convert_then_activate_dm_snapshot_and_read_back() {
    let Ok(control) = Control::open() else {
        eprintln!("skip: requires root for /dev/mapper/control");
        return;
    };
    let _ = Command::new("modprobe").arg("dm-snapshot").status();

    let chunk_bytes = CHUNK_SIZE_SECTORS as usize * 512;
    let n_chunks = 64usize;
    let image_len = n_chunks * chunk_bytes;

    // A raw image: distinctive data in a few chunks, zero elsewhere. The
    // zero chunks read back from the origin (dm-zero), the non-zero ones
    // from our COW.
    let mut image = vec![0u8; image_len];
    for &(idx, fill) in &[(0usize, 0x11u8), (3, 0x22), (17, 0x33), (63, 0x44)] {
        image[idx * chunk_bytes..(idx + 1) * chunk_bytes].fill(fill);
    }

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let raw_path = dir.join(format!("devmap-snap-raw-{pid}"));
    let cow_path = dir.join(format!("devmap-snap-cow-{pid}"));
    std::fs::write(&raw_path, &image).expect("write raw image");

    // Convert raw -> COW with the crate under test.
    let raw = File::open(&raw_path).expect("open raw");
    let mut cow_out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cow_path)
        .expect("create cow");
    let meta =
        devmap_snapshot::convert_sparse(&raw, image_len as u64, &mut cow_out, CHUNK_SIZE_SECTORS)
            .expect("write cow");
    assert_eq!(meta.exception_count, 4, "four non-zero chunks");
    drop(cow_out);
    std::fs::remove_file(&raw_path).ok();

    let sectors = (image_len / 512) as u64;

    // The COW loop must detach last, after the mappings it backs are gone.
    // Declaring it first puts its drop after theirs; the mappings
    // themselves are removed explicitly at the end of the test, since dm
    // devices are kernel state with no drop-based teardown.
    let cow_loop = LoopDevice::attach(cow_path);
    let cow_id = control.by_node(&cow_loop.path).expect("by_node cow").id();

    // Origin: a dm-zero device of the image's logical size.
    let origin = control
        .create(&format!("devmap-snap-origin-{pid}"))
        .expect("create origin");
    origin
        .builder()
        .add(0, sectors, Zero)
        .expect("add zero")
        .load()
        .expect("load zero");
    origin.resume().expect("resume origin");
    let origin_id = origin.id();

    // Snapshot: our COW over the zero origin.
    let snap = control
        .create(&format!("devmap-snap-{pid}"))
        .expect("create snapshot");
    snap.builder()
        .add(
            0,
            sectors,
            Snapshot {
                origin: origin_id,
                cow: cow_id,
                chunk_size_sectors: CHUNK_SIZE_SECTORS,
            },
        )
        .expect("add snapshot")
        .load()
        .expect("load snapshot — the kernel must accept our COW");
    snap.resume().expect("resume snapshot");

    // Read the mapped snapshot back and compare to the original image.
    // The kernel's own node is there the moment `resume` returns — no wait
    // for udev, because nothing here goes through /dev/mapper.
    let mut readback = vec![0u8; image_len];
    snap.open()
        .expect("open mapped snapshot device")
        .read_exact(&mut readback)
        .expect("read the mapped snapshot back");
    assert_eq!(readback, image, "dm-snapshot must serve the original image");

    // Teardown is ordered by dependency: the snapshot holds the origin
    // open, so it goes first, and only then may `cow_loop` detach on drop.
    // Deferred, because the nodes were open moments ago and udev may still
    // hold them; the kernel reclaims each once released.
    snap.remove_deferred().expect("remove snapshot");
    origin.remove_deferred().expect("remove origin");
}
