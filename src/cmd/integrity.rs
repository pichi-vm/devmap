// SPDX-License-Identifier: Apache-2.0

//! The `integrity` persona — `integritysetup`-equivalent operations.
//! Drives the dm-integrity two-step format and full-size table load via
//! [`devmap_linux`], with no external tool.

use std::fs::File;

use anyhow::{Context as _, Result};
use devmap_core::DevId;
use devmap_integrity::dm::Builder;
use devmap_integrity::dm::Mode;
use devmap_integrity::dm::Target as Integrity;

use crate::cli::{IntegrityClose, IntegrityCmd, IntegrityFormat, IntegrityOpen, IntegrityStatus};
use crate::control;

pub(crate) fn run(cmd: IntegrityCmd) -> Result<()> {
    match cmd {
        IntegrityCmd::Format(a) => format(&a),
        IntegrityCmd::Open(a) => open(&a),
        IntegrityCmd::Close(a) => close(&a),
        IntegrityCmd::Status(a) => status(&a),
    }
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

    let control = control::open()?;
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
    let sectors = devmap_integrity::Header::open(
        File::open(&a.device).with_context(|| format!("open {}", a.device.display()))?,
    )
    .context("read integrity header")?
    .data_sectors();
    let integrity = target(device, a.tag_size, &a.integrity, a.allow_discards);

    let control = control::open()?;
    let mapped = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    mapped
        .builder()
        .add(0, sectors, integrity)
        .context("build integrity table")?
        .load()
        .context("load integrity table")?;
    mapped.resume().context("resume")?;
    Ok(())
}

fn close(a: &IntegrityClose) -> Result<()> {
    control::remove(&a.name)
}

fn status(a: &IntegrityStatus) -> Result<()> {
    let device = control::by_name(&a.name)?;
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
