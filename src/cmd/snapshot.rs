// SPDX-License-Identifier: Apache-2.0

//! The `snapshot` persona — turn a raw image into a dm-snapshot
//! persistent COW ([`devmap_snapshot`]). No external tool; `lvcreate`
//! blanks a COW and lets the kernel format it, we write the store
//! directly.

use std::fs::OpenOptions;
use std::os::unix::fs::FileTypeExt as _;

use anyhow::{Context as _, Result};

use crate::cli::{SnapshotCmd, SnapshotConvert};

pub(crate) fn run(cmd: SnapshotCmd) -> Result<()> {
    match cmd {
        SnapshotCmd::Convert(a) => convert(&a),
    }
}

fn convert(a: &SnapshotConvert) -> Result<()> {
    let raw = std::fs::File::open(&a.raw).with_context(|| format!("open {}", a.raw.display()))?;
    let raw_len = raw
        .metadata()
        .with_context(|| format!("stat {}", a.raw.display()))?
        .len();

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

    let meta = devmap_snapshot::convert_sparse(&raw, raw_len, &mut cow, a.chunk_size)
        .with_context(|| format!("write COW to {}", a.cow.display()))?;

    let chunk_bytes = u64::from(a.chunk_size) * u64::from(devmap_snapshot::SECTOR_SIZE);
    println!("Converted {} -> {}", a.raw.display(), a.cow.display());
    println!("  Chunk size:      {} sectors", meta.chunk_size_sectors);
    println!("  Input chunks:    {}", raw_len.div_ceil(chunk_bytes));
    println!("  Exceptions:      {}", meta.exception_count);
    println!("  COW size:        {} bytes", meta.total_bytes);
    Ok(())
}
