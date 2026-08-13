// SPDX-License-Identifier: Apache-2.0

//! The `thin` persona — thin-provisioning-tools-equivalent operations on a
//! dm-thin metadata device, via [`devmap_persistent`].

use std::fs::File;
use std::io::Seek as _;

use anyhow::{Context as _, Result, bail};
use devmap_persistent::thin::Superblock;
use devmap_persistent::{thin, thin_xml};

use crate::cli::{ThinCheck, ThinCmd, ThinDump, ThinInfo, ThinRestore};

pub(crate) fn run(cmd: ThinCmd) -> Result<()> {
    match cmd {
        ThinCmd::Dump(a) => dump(&a),
        ThinCmd::Info(a) => info(&a),
        ThinCmd::Check(a) => check(&a),
        ThinCmd::Restore(a) => restore(&a),
    }
}

fn restore(a: &ThinRestore) -> Result<()> {
    let text = if a.input == std::path::Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("read XML from stdin")?
    } else {
        std::fs::read_to_string(&a.input).with_context(|| format!("read {}", a.input.display()))?
    };
    let pool = devmap_persistent::xml::parse(&text).context("parse the XML")?;

    let mut out = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&a.output)
        .with_context(|| format!("open {}", a.output.display()))?;
    // The destination's own size bounds the allocator.
    let len = out
        .seek(std::io::SeekFrom::End(0))
        .with_context(|| format!("size {}", a.output.display()))?;
    let metadata_blocks = len / devmap_persistent::BLOCK_SIZE as u64;

    devmap_persistent::restore::restore(&pool, &mut out, metadata_blocks)
        .with_context(|| format!("write metadata to {}", a.output.display()))?;
    println!(
        "Restored {} device(s) into {}",
        pool.devices.len(),
        a.output.display()
    );
    Ok(())
}

fn check(a: &ThinCheck) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let report = devmap_persistent::check::check(&file)
        .with_context(|| format!("check {}", a.metadata.display()))?;

    for error in &report.errors {
        eprintln!("devmap: {error}");
    }
    if report.is_clean() {
        println!("{}: metadata is consistent", a.metadata.display());
        println!("  Metadata blocks in use: {}", report.metadata_blocks_used);
        println!("  Data blocks in use:     {}", report.data_blocks_used);
        Ok(())
    } else {
        // Exit non-zero like thin_check, so scripts can branch on it.
        bail!("{} problem(s) found", report.errors.len())
    }
}

fn dump(a: &ThinDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let xml = thin_xml::dump(&file)
        .with_context(|| format!("read thin metadata from {}", a.metadata.display()))?;
    print!("{xml}");
    Ok(())
}

fn info(a: &ThinInfo) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let superblock = Superblock::read(&file).context("read thin superblock")?;
    let (data, metadata) = thin::space_maps(&file, &superblock).context("open space maps")?;
    let devices = thin::devices(&file, &superblock).context("read device details")?;

    println!("Thin metadata for {}", a.metadata.display());
    println!("  Version:          {}", superblock.version);
    println!("  Transaction:      {}", superblock.transaction_id);
    println!("  Time:             {}", superblock.time);
    println!("  Data block size:  {} sectors", superblock.data_block_size);
    println!(
        "  Data blocks:      {} used / {} total",
        data.root.nr_allocated, data.root.nr_blocks
    );
    println!(
        "  Metadata blocks:  {} used / {} total",
        metadata.root.nr_allocated, metadata.root.nr_blocks
    );
    println!("  Devices:          {}", devices.len());
    for (dev_id, details) in devices {
        println!(
            "    dev {dev_id}: {} mapped blocks, created at time {}",
            details.mapped_blocks, details.creation_time
        );
    }
    Ok(())
}
