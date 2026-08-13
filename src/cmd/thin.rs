// SPDX-License-Identifier: Apache-2.0

//! The `thin` persona — thin-provisioning-tools-equivalent operations on a
//! dm-thin metadata device, via [`devmap_persistent`].

use std::fs::File;

use anyhow::{Context as _, Result};
use devmap_persistent::thin::Superblock;
use devmap_persistent::{thin, thin_xml};

use crate::cli::{ThinCmd, ThinDump, ThinInfo};

pub(crate) fn run(cmd: ThinCmd) -> Result<()> {
    match cmd {
        ThinCmd::Dump(a) => dump(&a),
        ThinCmd::Info(a) => info(&a),
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
