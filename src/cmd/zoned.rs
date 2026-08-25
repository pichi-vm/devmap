// SPDX-License-Identifier: Apache-2.0

//! The `zoned` persona — `dmzadm`-equivalent operations. Formats a zoned
//! block device with [`devmap_zoned`] (no C `dmzadm`) and activates the
//! dm-zoned target over it via [`devmap_linux`].

use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use devmap_linux::DevId;
use devmap_linux::targets::Zoned;
use devmap_zoned::{BLOCK_SIZE, FormatOptions, Superblock};

use crate::cli::{ZonedCheck, ZonedCmd, ZonedFormat, ZonedStart, ZonedStatus, ZonedStop};
use crate::size::SECTOR;
use crate::{control, urandom, uuid};

/// Sectors per [`BLOCK_SIZE`] metadata block.
const SECTORS_PER_BLOCK: u64 = BLOCK_SIZE as u64 / SECTOR;

pub(crate) fn run(cmd: ZonedCmd) -> Result<()> {
    match cmd {
        ZonedCmd::Format(a) => format(&a),
        ZonedCmd::Check(a) => check(&a),
        ZonedCmd::Start(a) => start(&a),
        ZonedCmd::Stop(a) => stop(&a),
        ZonedCmd::Status(a) => status(&a),
    }
}

/// Read and validate the primary superblock (block 0) of a zoned device.
fn read_superblock(dev: &Path) -> Result<Superblock> {
    let file = File::open(dev).with_context(|| format!("open {}", dev.display()))?;
    let mut block = [0u8; BLOCK_SIZE];
    file.read_exact_at(&mut block, 0)
        .with_context(|| format!("read superblock from {}", dev.display()))?;
    Superblock::from_block(&block).context("parse dm-zoned superblock")
}

fn format(a: &ZonedFormat) -> Result<()> {
    let mut label = [0u8; 32];
    if let Some(text) = &a.label {
        let bytes = text.as_bytes();
        let n = bytes.len().min(label.len());
        label[..n].copy_from_slice(&bytes[..n]);
    }
    let dmz_uuid = pick_uuid(a.uuid.as_deref(), "--uuid")?;
    let dev_uuid = pick_uuid(a.dev_uuid.as_deref(), "--dev-uuid")?;

    let options = FormatOptions {
        label,
        dmz_uuid,
        dev_uuid,
        reserved_seq: a.seq,
    };
    let layout = devmap_zoned::format(&a.device, &options)
        .with_context(|| format!("format {}", a.device.display()))?;

    let geometry = layout.geometry();
    println!("Formatted {}", a.device.display());
    println!("  UUID:            {}", uuid::format(&dmz_uuid));
    println!("  Total zones:     {}", geometry.total_zones);
    println!("  Zone size:       {} blocks", geometry.zone_size_blocks);
    println!("  Data chunks:     {}", layout.nr_chunks());
    println!("  Metadata blocks: {} (per set)", layout.nr_meta_blocks());
    println!("  Logical sectors: {}", layout.logical_sectors());
    Ok(())
}

fn check(a: &ZonedCheck) -> Result<()> {
    let sb = read_superblock(&a.device)?;
    println!("Superblock for {} is valid", a.device.display());
    println!("  Version:         {}", sb.version);
    println!("  Generation:      {}", sb.generation);
    println!("  Data chunks:     {}", sb.nr_chunks);
    println!("  Metadata blocks: {}", sb.nr_meta_blocks);
    println!("  Reserved seq:    {}", sb.nr_reserved_seq);
    println!("  UUID:            {}", uuid::format(&sb.dmz_uuid));
    Ok(())
}

fn start(a: &ZonedStart) -> Result<()> {
    // Recover the logical size from the on-disk chunk count and the device's
    // zone geometry, so no format-time options need restating.
    let sb = read_superblock(&a.device)?;
    let geometry = devmap_zoned::report_zones(&a.device)
        .with_context(|| format!("report zones of {}", a.device.display()))?;
    let length = u64::from(sb.nr_chunks) * u64::from(geometry.zone_size_blocks) * SECTORS_PER_BLOCK;

    let device = DevId::from_path(&a.device).context("resolve zoned device")?;
    let name = a.name.clone().unwrap_or_else(|| default_name(&a.device));

    let control = control::open()?;
    let mapped = control
        .create(&name)
        .with_context(|| format!("create {name}"))?;
    mapped
        .builder()
        .add(0, length, Zoned { device })
        .context("build zoned table")?
        .load()
        .context("load zoned table")?;
    mapped.resume().context("resume")?;
    println!("{name}");
    Ok(())
}

fn stop(a: &ZonedStop) -> Result<()> {
    control::remove(&a.name)
}

fn status(a: &ZonedStatus) -> Result<()> {
    let device = control::by_name(&a.name)?;
    if let Some(info) = device
        .target::<Zoned>(0)
        .info()
        .context("read zoned status")?
    {
        println!("{info}");
    } else {
        println!("{}: no zoned target at sector 0", a.name);
    }
    Ok(())
}

/// Parse a supplied UUID or generate a random one.
fn pick_uuid(supplied: Option<&str>, flag: &str) -> Result<[u8; 16]> {
    if let Some(s) = supplied {
        uuid::parse(s).with_context(|| format!("parse {flag}"))
    } else {
        let bytes = urandom::bytes(16).context("read random uuid")?;
        Ok(bytes.try_into().expect("urandom(16) is 16 bytes"))
    }
}

/// The mapped-device name to use when `start` isn't given one: `dmz-<basename>`.
fn default_name(device: &Path) -> String {
    let base = device.file_name().map_or_else(
        || "device".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    format!("dmz-{base}")
}
