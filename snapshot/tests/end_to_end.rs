// SPDX-License-Identifier: Apache-2.0

//! Kernel acceptance: the format is right only if dm-snapshot maps a store
//! this crate wrote and serves the image back.
//!
//! Requires root, for `/dev/mapper/control` and losetup; skips otherwise.

#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::PathBuf;
use std::process::Command;

use devmap_linux::targets::{Snapshot, Zero as DmZero};
use devmap_linux::{Control, Device};
use devmap_snapshot::{ChunkSize, Layer, SyncData};

/// 4 KiB chunks: the kernel minimum, so the test images stay small.
const SIZE: usize = 4096;

fn chunk_size() -> ChunkSize {
    ChunkSize::from_sectors(8).expect("8 sectors is 4 KiB")
}

/// A backing file attached as a loop device; detaches and deletes on drop.
struct LoopDevice {
    path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    fn attach(file_path: PathBuf) -> Self {
        let output = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&file_path)
            .output()
            .expect("run losetup");
        assert!(
            output.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let path = String::from_utf8(output.stdout)
            .expect("losetup prints a path")
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

/// An image with distinctive data in a few chunks and zeroes elsewhere.
fn image(chunks: usize, marked: &[(usize, u8)]) -> Vec<u8> {
    let mut image = vec![0; chunks * SIZE];
    for &(index, byte) in marked {
        image[index * SIZE..(index + 1) * SIZE].fill(byte);
    }
    image
}

fn temporary(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("devmap-snap-{name}-{}", std::process::id()))
}

/// Reads the whole of a mapped device back.
fn read_back(device: &Device, length: usize) -> Vec<u8> {
    let mut contents = vec![0; length];
    device
        .open()
        .expect("open the mapped device")
        .read_exact(&mut contents)
        .expect("read the mapped device back");
    contents
}

#[test]
fn the_kernel_serves_an_image_from_a_store_this_crate_wrote() {
    let Ok(control) = Control::open() else {
        eprintln!("skip: requires root for /dev/mapper/control");
        return;
    };
    let _ = Command::new("modprobe").arg("dm-snapshot").status();

    let chunks = 64;
    let contents = image(chunks, &[(0, 0x11), (3, 0x22), (17, 0x33), (63, 0x44)]);
    let length = contents.len();

    let raw_path = temporary("raw");
    let cow_path = temporary("cow");
    std::fs::write(&raw_path, &contents).expect("write the raw image");

    // Convert with the crate under test.
    let raw = File::open(&raw_path).expect("open the raw image");
    let mut cow_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cow_path)
        .expect("create the store");
    let converted =
        devmap_snapshot::convert_sparse(&raw, length as u64, &mut cow_file, chunk_size())
            .expect("convert");
    assert_eq!(converted.exception_count, 4, "four non-zero chunks");
    drop(cow_file);
    std::fs::remove_file(&raw_path).ok();

    let sectors = (length / 512) as u64;

    // The store's loop device must detach after the mappings it backs are
    // gone, so it is declared first and dropped last.
    let cow_loop = LoopDevice::attach(cow_path);
    let cow_id = control.by_node(&cow_loop.path).expect("cow by node").id();

    let origin = control
        .create(&format!("devmap-snap-origin-{}", std::process::id()))
        .expect("create the origin");
    origin
        .builder()
        .add(0, sectors, DmZero)
        .expect("add dm-zero")
        .load()
        .expect("load dm-zero");
    origin.resume().expect("resume the origin");

    let snapshot = control
        .create(&format!("devmap-snap-{}", std::process::id()))
        .expect("create the snapshot");
    snapshot
        .builder()
        .add(
            0,
            sectors,
            Snapshot {
                origin: origin.id(),
                cow: cow_id,
                chunk_size_sectors: chunk_size().sectors(),
            },
        )
        .expect("add the snapshot")
        .load()
        .expect("load it — the kernel must accept our store");
    snapshot.resume().expect("resume the snapshot");

    assert_eq!(
        read_back(&snapshot, length),
        contents,
        "dm-snapshot must serve the original image"
    );

    // Teardown is ordered by dependency: the snapshot holds the origin open.
    // Deferred, because the nodes were open moments ago.
    snapshot.remove_deferred().expect("remove the snapshot");
    origin.remove_deferred().expect("remove the origin");
}

#[test]
fn the_kernel_accepts_a_store_this_crate_merged_down() {
    let Ok(control) = Control::open() else {
        eprintln!("skip: requires root for /dev/mapper/control");
        return;
    };
    let _ = Command::new("modprobe").arg("dm-snapshot").status();

    let chunks = 32u64;
    let length = usize::try_from(chunks).expect("a test-sized image") * SIZE;
    let marked: &[(usize, u8)] = &[(2, 0xaa), (9, 0xbb), (31, 0xcc)];

    let origin_path = temporary("merge-origin");
    let cow_path = temporary("merge-cow");
    std::fs::write(&origin_path, vec![0; length]).expect("write the origin image");

    // Write a layer over the origin, then merge it straight back down.
    {
        let mut origin_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&origin_path)
            .expect("open the origin");
        let cow_chunks = chunk_size().cow_chunks(chunks).expect("layout");
        let cow_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&cow_path)
            .expect("create the store");
        cow_file
            .set_len(cow_chunks * SIZE as u64)
            .expect("size the store");

        let mut layer = Layer::create(
            &mut origin_file,
            cow_file,
            length as u64,
            cow_chunks * SIZE as u64,
            chunk_size(),
        )
        .expect("create layer");
        for &(index, byte) in marked {
            layer
                .seek(SeekFrom::Start(index as u64 * SIZE as u64))
                .unwrap();
            layer
                .write_all(&[byte; SIZE])
                .expect("write a chunk into the store");
        }
        layer.sync_data().expect("persist");
        drop(layer);

        let layer = Layer::open(
            &mut origin_file,
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&cow_path)
                .expect("reopen the store"),
            length as u64,
            cow_chunks * SIZE as u64,
        )
        .expect("open layer");
        layer.merge().run().expect("merge the store down");
    }

    // The origin now holds the merged image, and the store is empty. The
    // kernel must accept that store and serve the origin through it
    // unchanged.
    let expected = image(usize::try_from(chunks).expect("a test-sized image"), marked);
    assert_eq!(
        std::fs::read(&origin_path).expect("read the origin"),
        expected,
        "the merge must have written every chunk back"
    );

    let sectors = chunks * SIZE as u64 / 512;
    let cow_loop = LoopDevice::attach(cow_path);
    let origin_loop = LoopDevice::attach(origin_path);
    let cow_id = control.by_node(&cow_loop.path).expect("cow by node").id();
    let origin_id = control
        .by_node(&origin_loop.path)
        .expect("origin by node")
        .id();

    let snapshot = control
        .create(&format!("devmap-snap-merged-{}", std::process::id()))
        .expect("create the snapshot");
    snapshot
        .builder()
        .add(
            0,
            sectors,
            Snapshot {
                origin: origin_id,
                cow: cow_id,
                chunk_size_sectors: chunk_size().sectors(),
            },
        )
        .expect("add the snapshot")
        .load()
        .expect("load it — the kernel must accept our merged store");
    snapshot.resume().expect("resume the snapshot");

    assert_eq!(
        read_back(&snapshot, length),
        expected,
        "an emptied store must read straight through to the origin"
    );

    snapshot.remove_deferred().expect("remove the snapshot");
    drop(origin_loop);
    drop(cow_loop);
}
