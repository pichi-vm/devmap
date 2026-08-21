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

use common::{BIN, LoopDevice, have_dm, run};

/// 4 KiB chunks (8 sectors, the kernel minimum) keep the image small.
const CHUNK_SECTORS: u64 = 8;
const CHUNK_BYTES: u64 = CHUNK_SECTORS * 512;

#[test]
fn convert_reads_the_whole_of_a_block_device_source() {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }

    // A source with data in some chunks and zeros in others: the non-zero
    // ones become exceptions in the COW, so the count proves how much of
    // the device was actually read.
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
    assert!(
        out.contains(&format!("Exceptions:      {}", filled.len())),
        "every non-zero chunk becomes an exception: {out}"
    );
}
