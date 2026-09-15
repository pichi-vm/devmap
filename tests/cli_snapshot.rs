// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `snapshot` persona: convert a raw image
//! held on a real block device into a persistent COW.
//!
//! A block device is the case worth a root test. Its size lives in the
//! device, not in its inode, so `metadata().len()` reads back as zero for
//! one and a conversion sized that way silently produces an empty COW
//! with a successful exit status. Nothing about that failure is visible
//! without a real block device to point the command at.
//!
//! Skips cleanly without root (losetup needs it).

mod common;

use std::fs::OpenOptions;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use common::{BIN, LoopDevice, have_dm, run};
use devmap_snapshot::{Layer, traits::std::Open};
use devmap_zero::Zero;

/// 4 KiB chunks (8 sectors, the kernel minimum) keep the image small.
const CHUNK_SECTORS: u64 = 8;
const CHUNK_BYTES: u64 = CHUNK_SECTORS * 512;

#[test]
fn convert_composes_a_zero_origin_with_sparse_source_extents() {
    let length = 8 * CHUNK_BYTES;
    let chunk_bytes = usize::try_from(CHUNK_BYTES).expect("chunk fits in memory");
    let length_usize = usize::try_from(length).expect("image fits in memory");
    let raw_path =
        std::env::temp_dir().join(format!("devmap-snap-regular-src-{}", std::process::id()));
    let cow_path =
        std::env::temp_dir().join(format!("devmap-snap-regular-cow-{}", std::process::id()));
    let mut raw = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&raw_path)
        .expect("create sparse source");
    raw.set_len(length).expect("size sparse source");
    raw.seek(SeekFrom::Start(CHUNK_BYTES)).unwrap();
    raw.write_all(&vec![0; chunk_bytes]).unwrap();
    raw.seek(SeekFrom::Start(3 * CHUNK_BYTES))
        .expect("seek sparse source");
    raw.write_all(&vec![0x5a; chunk_bytes])
        .expect("write sparse extent");
    drop(raw);

    let (ok, out) = run(
        BIN,
        &[
            "snapshot",
            "convert",
            raw_path.to_str().unwrap(),
            cow_path.to_str().unwrap(),
            "--chunk-size",
            &CHUNK_SECTORS.to_string(),
        ],
    );
    assert!(ok, "convert should succeed: {out}");
    assert_eq!(
        std::fs::metadata(&cow_path).unwrap().len(),
        10 * CHUNK_BYTES
    );

    let mut cow = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&cow_path)
        .expect("open converted COW");
    let mut layer = Layer::open(Zero::new(length), &mut cow).expect("open converted layer");
    let mut actual = Vec::new();
    layer
        .read_to_end(&mut actual)
        .expect("read converted image");
    let mut expected = vec![0; length_usize];
    expected[3 * chunk_bytes..4 * chunk_bytes].fill(0x5a);
    assert_eq!(actual, expected);
    drop(layer);

    cow.seek(SeekFrom::Start(CHUNK_BYTES)).unwrap();
    let mut metadata = vec![0; chunk_bytes];
    cow.read_exact(&mut metadata).unwrap();
    assert_eq!(&metadata[..8], &3_u64.to_le_bytes());
    assert_eq!(&metadata[8..16], &2_u64.to_le_bytes());
    assert!(metadata[16..].iter().all(|byte| *byte == 0));

    std::fs::remove_file(raw_path).ok();
    std::fs::remove_file(cow_path).ok();
}

#[test]
fn convert_preserves_an_unaligned_tail() {
    let directory = tempfile::tempdir().unwrap();
    let raw_path = directory.path().join("raw");
    let cow_path = directory.path().join("cow");
    let mut expected = vec![0; 4 * 4096 + 17];
    expected[3 * 4096 + 5..3 * 4096 + 12].copy_from_slice(b"payload");
    *expected.last_mut().unwrap() = 0x55;
    std::fs::write(&raw_path, &expected).unwrap();

    let (ok, out) = run(
        BIN,
        &[
            "snapshot",
            "convert",
            raw_path.to_str().unwrap(),
            cow_path.to_str().unwrap(),
            "--chunk-size",
            "8",
        ],
    );
    assert!(ok, "convert should succeed: {out}");
    assert!(out.contains("Input chunks:    5"), "{out}");
    let cow = std::fs::File::open(&cow_path).unwrap();
    let mut layer = Layer::open(Zero::new(u64::try_from(expected.len()).unwrap()), cow).unwrap();
    let mut actual = Vec::new();
    layer.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn convert_rejects_aliases_before_modifying_the_source() {
    let directory = tempfile::tempdir().unwrap();
    let raw_path = directory.path().join("raw");
    let alias_path = directory.path().join("alias");
    let expected = vec![0x55; 4 * 4096];
    std::fs::write(&raw_path, &expected).unwrap();
    std::fs::hard_link(&raw_path, &alias_path).unwrap();

    for output in [&raw_path, &alias_path] {
        let (ok, _, error) = common::run_capturing(
            BIN,
            &[
                "snapshot",
                "convert",
                raw_path.to_str().unwrap(),
                output.to_str().unwrap(),
                "--chunk-size",
                "8",
            ],
        );
        assert!(!ok);
        assert!(error.contains("input and COW storage alias"), "{error}");
        assert_eq!(std::fs::read(&raw_path).unwrap(), expected);
    }
}

#[test]
fn convert_reads_the_whole_of_a_block_device_source() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }

    // A source with data in some chunks and zeros in others.
    let n_chunks = 64u64;
    let image_len = n_chunks * CHUNK_BYTES;
    let mut image = vec![0u8; usize::try_from(image_len).expect("image fits in memory")];
    let filled = [0usize, 3, 17, 63];
    for (n, &idx) in filled.iter().enumerate() {
        let start = idx * usize::try_from(CHUNK_BYTES).expect("chunk fits");
        let end = start + usize::try_from(CHUNK_BYTES).expect("chunk fits");
        image[start..end].fill(0x11 + u8::try_from(n).expect("few chunks"));
    }
    let raw_path = std::env::temp_dir().join(format!("devmap-snap-src-{}", std::process::id()));
    std::fs::write(&raw_path, &image).expect("write the source image");
    let raw = LoopDevice::attach(raw_path);

    let cow = LoopDevice::sparse("snapshot-cow", 16 * 1024 * 1024);

    let chunk = CHUNK_SECTORS.to_string();
    let (ok, out) = run(
        BIN,
        &[
            "snapshot",
            "convert",
            &raw.path,
            &cow.path,
            "--chunk-size",
            &chunk,
        ],
    );
    assert!(ok, "convert should succeed: {out}");

    // The regression: sizing the source through its inode yields zero, and
    // the command then reports no input and no exceptions while still
    // exiting successfully.
    assert!(
        out.contains(&format!("Input chunks:    {n_chunks}")),
        "convert must read the whole block device, not stop at a zero size: {out}"
    );
}
