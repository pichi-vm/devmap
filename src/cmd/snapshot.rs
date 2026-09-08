// SPDX-License-Identifier: Apache-2.0

//! The `snapshot` persona — turn a raw image into a dm-snapshot
//! persistent COW ([`devmap_snapshot`]). No external tool; `lvcreate`
//! blanks a COW and lets the kernel format it, we write the store
//! directly.

use std::fs::OpenOptions;
use std::os::unix::fs::FileTypeExt as _;

use anyhow::{Context as _, Result};
use devmap_snapshot::ChunkSize;

use crate::cli::{SnapshotCmd, SnapshotConvert};
use crate::size;

pub(crate) fn run(cmd: SnapshotCmd) -> Result<()> {
    match cmd {
        SnapshotCmd::Convert(a) => convert(&a),
    }
}

fn convert(a: &SnapshotConvert) -> Result<()> {
    let raw = std::fs::File::open(&a.raw).with_context(|| format!("open {}", a.raw.display()))?;
    // Sized by seeking, not by `metadata().len()`: the source may be a
    // block device, whose size is not recorded in its inode.
    let raw_len = size::of(&raw).with_context(|| format!("size {}", a.raw.display()))?;

    // A regular file is truncated so no stale tail follows the COW; a block
    // device is written in place (it can't be truncated and is already sized).
    let cow_is_block = std::fs::metadata(&a.cow).is_ok_and(|m| m.file_type().is_block_device());
    let mut cow = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&a.cow)
        .with_context(|| format!("open {}", a.cow.display()))?;
    if !cow_is_block {
        cow.set_len(0).context("truncate COW output")?;
    }

    let chunk_size = ChunkSize::from_sectors(a.chunk_size).context("chunk size")?;
    let converted = devmap_snapshot::convert_sparse(&raw, raw_len, &mut cow, chunk_size)
        // Both devices are named: the conversion reads one and writes the
        // other, and the error alone doesn't say which end faulted.
        .with_context(|| format!("convert {} into {}", a.raw.display(), a.cow.display()))?;

    println!("Converted {} -> {}", a.raw.display(), a.cow.display());
    println!("  Chunk size:      {} sectors", chunk_size.sectors());
    println!(
        "  Input chunks:    {}",
        raw_len.div_ceil(chunk_size.bytes().get())
    );
    println!("  Exceptions:      {}", converted.exception_count);
    println!("  COW size:        {} bytes", converted.cow_bytes);
    Ok(())
}
