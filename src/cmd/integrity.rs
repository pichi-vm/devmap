// SPDX-License-Identifier: Apache-2.0

//! The `integrity` persona — `integritysetup`-equivalent operations.
//! Drives the dm-integrity two-step format and full-size table load via
//! [`devmap_linux`], with no external tool.

use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use devmap_linux::targets::integrity::{Builder, Integrity, Mode};
use devmap_linux::{Control, DevId, Device};

use crate::cli::{IntegrityClose, IntegrityCmd, IntegrityFormat, IntegrityOpen, IntegrityStatus};

pub(crate) fn run(cmd: IntegrityCmd) -> Result<()> {
    match cmd {
        IntegrityCmd::Format(a) => format(&a),
        IntegrityCmd::Open(a) => open(&a),
        IntegrityCmd::Close(a) => close(&a),
        IntegrityCmd::Status(a) => status(&a),
    }
}

/// Read `provided_data_sectors` from a formatted device's superblock — a
/// little-endian u64 at offset 16, after magic/version/tag geometry.
fn provided_data_sectors(dev: &Path) -> Result<u64> {
    let file = File::open(dev).with_context(|| format!("open {}", dev.display()))?;
    let mut sb = [0u8; 24];
    file.read_exact_at(&mut sb, 0)
        .with_context(|| format!("read superblock from {}", dev.display()))?;
    Ok(u64::from_le_bytes(sb[16..24].try_into().unwrap()))
}

/// Build the integrity target for a device from the persona's shared
/// options (internal hash, tag size, discards). Journaled mode matches
/// integritysetup's standalone default.
fn target(
    device: DevId,
    tag_size: Option<u32>,
    integrity: &str,
    allow_discards: bool,
) -> Integrity {
    let mut builder: Builder =
        Integrity::builder(device, 0, Mode::Journaled).internal_hash(integrity);
    if let Some(size) = tag_size {
        builder = builder.tag_size(size);
    }
    builder.allow_discards(allow_discards).build()
}

fn format(a: &IntegrityFormat) -> Result<()> {
    let device = DevId::from_path(&a.device).context("resolve device")?;
    let integrity = target(device, a.tag_size, &a.integrity, a.allow_discards);

    let control = Control::open().context("open /dev/mapper/control")?;
    // A throwaway name for the transient format mapping; it is removed
    // before this returns, leaving only the superblock on the device.
    let tmp = format!("devmap-integ-format-{}", std::process::id());
    let sectors = integrity
        .format(&control, &tmp, &a.device)
        .with_context(|| format!("format {}", a.device.display()))?;

    println!("Formatted {} for dm-integrity", a.device.display());
    println!("  Algorithm:             {}", a.integrity);
    if let Some(size) = a.tag_size {
        println!("  Tag size:              {size}");
    }
    println!("  Provided data sectors: {sectors}");
    Ok(())
}

fn open(a: &IntegrityOpen) -> Result<()> {
    let device = DevId::from_path(&a.device).context("resolve device")?;
    let sectors = provided_data_sectors(&a.device)?;
    let integrity = target(device, a.tag_size, &a.integrity, a.allow_discards);

    let control = Control::open().context("open /dev/mapper/control")?;
    let removed = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    removed
        .builder()
        .add(0, sectors, integrity)
        .context("build integrity table")?
        .load()
        .context("load integrity table")?;
    removed.resume().context("resume")?;
    let _ = Device::from(removed);
    Ok(())
}

fn close(a: &IntegrityClose) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?
        .0
        .remove()
        .context("remove")
}

fn status(a: &IntegrityStatus) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    let (device, _) = control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?;
    if let Some(info) = device
        .target::<Integrity>(0)
        .info()
        .context("read integrity status")?
    {
        println!("{info}");
    } else {
        println!("{}: no integrity target at sector 0", a.name);
    }
    Ok(())
}
