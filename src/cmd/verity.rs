// SPDX-License-Identifier: Apache-2.0

//! The `verity` persona — dm-verity formatting and activation.

use std::fs::{File, OpenOptions};
use std::num::NonZeroU32;

use anyhow::{Context as _, Result};
use devmap_core::DevId;
use devmap_verity::dm::Target as VerityTarget;
use devmap_verity::traits::std::{
    Format as _, Geometry as _, Open as _, OpenHashes as _, Scale as _, SliceBytes as _,
};
use devmap_verity::{Formatter, HashType, Hashes, Verity};

use crate::cli::{
    VerityClose, VerityCmd, VerityDump, VerityFormat, VerityOpen, VerityStatus, VerityVerify,
};
use crate::{control, hex, urandom, uuid};

pub(crate) fn run(cmd: VerityCmd) -> Result<()> {
    match cmd {
        VerityCmd::Format(arguments) => format(&arguments),
        VerityCmd::Open(arguments) => open(&arguments),
        VerityCmd::Close(arguments) => close(&arguments),
        VerityCmd::Verify(arguments) => verify(&arguments),
        VerityCmd::Dump(arguments) => dump(&arguments),
        VerityCmd::Status(arguments) => status(&arguments),
    }
}

fn format(arguments: &VerityFormat) -> Result<()> {
    let salt = match &arguments.salt {
        Some(encoded) => hex::decode(encoded).context("parse --salt")?,
        None => urandom::bytes(32).context("read random salt")?,
    };
    let uuid = if let Some(encoded) = &arguments.uuid {
        uuid::parse(encoded).context("parse --uuid")?
    } else {
        urandom::bytes(16)
            .context("read random UUID")?
            .try_into()
            .expect("requested 16 random bytes")
    };
    let data = File::open(&arguments.data_dev)
        .with_context(|| format!("open {}", arguments.data_dev.display()))?;
    let data_block_size =
        NonZeroU32::new(arguments.data_block_size).context("invalid data block size")?;
    let mut data = data
        .scale_to(data_block_size)
        .context("apply data block size")?;
    let data_blocks = data.count().context("read data block count")?;
    let formatter = Formatter::new(uuid)
        .hash_type(HashType::Normal)
        .salt(&salt)
        .context("set salt")?;
    let mut hashes = OpenOptions::new()
        .write(true)
        .open(&arguments.hash_dev)
        .with_context(|| format!("open {}", arguments.hash_dev.display()))?;
    let hash_block_size =
        NonZeroU32::new(arguments.hash_block_size).context("invalid verity hash block size")?;
    let root = if arguments.hash_offset == 0 {
        let mut output = (&mut hashes)
            .scale_to(hash_block_size)
            .context("apply hash block size")?;
        formatter
            .format(&mut data, &mut output)
            .context("format verity hash device")?
    } else {
        let mut output = (&mut hashes)
            .scale_to(hash_block_size)
            .context("apply hash block size")?
            .slice_bytes(arguments.hash_offset..)
            .context("select hash-device region")?;
        formatter
            .format(&mut data, &mut output)
            .context("format verity hash device")?
    };
    hashes.sync_all().context("sync hash device")?;

    println!(
        "VERITY header information for {}",
        arguments.hash_dev.display()
    );
    println!("UUID:            \t{}", uuid::format(&uuid));
    println!("Hash type:       \t{}", HashType::Normal);
    println!("Data blocks:     \t{data_blocks}");
    println!("Data block size: \t{}", arguments.data_block_size);
    println!("Hash block size: \t{}", arguments.hash_block_size);
    println!("Hash algorithm:  \tsha256");
    println!("Salt:            \t{}", hex::encode(&salt));
    println!("Root hash:       \t{}", hex::encode(&root));
    Ok(())
}

fn open(arguments: &VerityOpen) -> Result<()> {
    let hashes = Hashes::open(
        File::open(&arguments.hash_dev)
            .with_context(|| format!("open {}", arguments.hash_dev.display()))?
            .slice_bytes(arguments.hash_offset..)
            .context("select hash-device region")?,
    )
    .context("read verity header")?;
    let digest = hex::decode(&arguments.root_hash).context("parse root hash")?;
    let target = devmap_verity::dm::Builder::from(hashes.header())
        .header_offset_bytes(arguments.hash_offset)
        .context("set hash header location")?
        .build(
            DevId::from_path(&arguments.data_dev).context("resolve data device")?,
            DevId::from_path(&arguments.hash_dev).context("resolve hash device")?,
            &digest,
        )
        .context("construct verity target")?;

    let control = control::open()?;
    let device = control
        .create(&arguments.name)
        .with_context(|| format!("create {}", arguments.name))?;
    target
        .add_full(device.builder())
        .context("build verity table")?
        .load()
        .context("load verity table")?;
    device.resume().context("resume")?;
    Ok(())
}

fn close(arguments: &VerityClose) -> Result<()> {
    control::remove(&arguments.name)
}

fn verify(arguments: &VerityVerify) -> Result<()> {
    let root = hex::decode(&arguments.root_hash).context("parse root hash")?;
    let data = File::open(&arguments.data_dev)
        .with_context(|| format!("open {}", arguments.data_dev.display()))?;
    let hashes = File::open(&arguments.hash_dev)
        .with_context(|| format!("open {}", arguments.hash_dev.display()))?;
    let hashes = Hashes::open(
        hashes
            .slice_bytes(arguments.hash_offset..)
            .context("select hash-device region")?,
    )
    .context("read verity header")?;
    let mut device = Verity::open(data, hashes, &root).context("open authenticated view")?;
    std::io::copy(&mut device, &mut std::io::sink()).context("verify data device")?;
    println!("Verification successful.");
    Ok(())
}

fn dump(arguments: &VerityDump) -> Result<()> {
    let hashes = Hashes::open(
        File::open(&arguments.hash_dev)
            .with_context(|| format!("open {}", arguments.hash_dev.display()))?,
    )
    .context("read verity header")?;
    let metadata = hashes.header();
    println!(
        "VERITY header information for {}",
        arguments.hash_dev.display()
    );
    println!("UUID:            \t{}", uuid::format(&metadata.uuid()));
    println!("Hash type:       \t{}", metadata.hash_type());
    println!("Data blocks:     \t{}", metadata.data_blocks());
    println!("Data block size: \t{}", metadata.data_block_size().get());
    println!("Hash block size: \t{}", metadata.hash_block_size().get());
    println!("Hash algorithm:  \t{}", metadata.algorithm());
    println!("Salt:            \t{}", hex::encode(metadata.salt()));
    Ok(())
}

fn status(arguments: &VerityStatus) -> Result<()> {
    let device = control::by_name(&arguments.name)?;
    if let Some(info) = device
        .target::<VerityTarget>(0)
        .info()
        .context("read verity status")?
    {
        let state = if info.corrupted {
            "corrupted"
        } else {
            "verified"
        };
        println!("{}/{state} status: {info}", arguments.name);
    } else {
        println!("{}: no verity target at sector 0", arguments.name);
    }
    Ok(())
}
