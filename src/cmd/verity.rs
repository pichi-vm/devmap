// SPDX-License-Identifier: Apache-2.0

//! The `verity` persona — `veritysetup`-equivalent operations. Composes
//! the on-disk hash tree ([`devmap_verity`]) with a dm-verity table load
//! ([`devmap_linux`]).

use std::fs::{File, OpenOptions};
use std::io::{Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;

use anyhow::{Context as _, Result, bail};
use devmap_linux::targets::Verity;
use devmap_linux::{Control, DevId, Device};
use devmap_verity::{Superblock, VerityBuilder, VerityParams, feed_from_reader};

use crate::cli::{
    VerityClose, VerityCmd, VerityDump, VerityFormat, VerityOpen, VerityStatus, VerityVerify,
};
use crate::{hex, urandom};

/// Bytes per sector — the unit of a dm table's start/length.
const SECTOR: u64 = 512;

pub(crate) fn run(cmd: VerityCmd) -> Result<()> {
    match cmd {
        VerityCmd::Format(a) => format(&a),
        VerityCmd::Open(a) => open(&a),
        VerityCmd::Close(a) => close(&a),
        VerityCmd::Verify(a) => verify(&a),
        VerityCmd::Dump(a) => dump(&a),
        VerityCmd::Status(a) => status(&a),
    }
}

/// Read the 512-byte superblock from the start of a hash device.
fn read_superblock(hash_dev: &std::path::Path) -> Result<Superblock> {
    let file = File::open(hash_dev).with_context(|| format!("open {}", hash_dev.display()))?;
    let mut sb = [0u8; devmap_verity::VERITY_SB_SIZE];
    file.read_exact_at(&mut sb, 0)
        .with_context(|| format!("read superblock from {}", hash_dev.display()))?;
    Superblock::from_bytes(&sb).context("parse verity superblock")
}

fn format(a: &VerityFormat) -> Result<()> {
    let salt = match &a.salt {
        Some(hexstr) => hex::decode(hexstr).context("parse --salt")?,
        None => urandom::bytes(32).context("read random salt")?,
    };
    let uuid = if let Some(s) = &a.uuid {
        parse_uuid(s).context("parse --uuid")?
    } else {
        let bytes = urandom::bytes(16).context("read random uuid")?;
        bytes.try_into().expect("urandom(16) is 16 bytes")
    };
    let params = VerityParams {
        data_block_size: a.data_block_size,
        hash_block_size: a.hash_block_size,
        salt,
        uuid,
    };

    // Stream the data device through the builder rather than loading it.
    let mut data =
        File::open(&a.data_dev).with_context(|| format!("open {}", a.data_dev.display()))?;
    let size = data.seek(SeekFrom::End(0)).context("size data device")?;
    data.rewind().context("rewind data device")?;

    let dbs = params.data_block_size as usize;
    let mut builder = VerityBuilder::new(&params).context("init verity builder")?;
    feed_from_reader(&mut data, &mut builder, dbs).context("hash data device")?;
    let out = builder.finalize();

    // Write the tree blob at the hash device offset (default 0).
    let hash = OpenOptions::new()
        .write(true)
        .open(&a.hash_dev)
        .with_context(|| format!("open {}", a.hash_dev.display()))?;
    hash.write_all_at(&out.blob, a.hash_offset)
        .context("write hash tree")?;
    hash.sync_all().context("sync hash device")?;

    let data_blocks = size.div_ceil(u64::from(params.data_block_size));
    println!("VERITY header information for {}", a.hash_dev.display());
    println!("UUID:            \t{}", format_uuid(&params.uuid));
    println!("Hash type:       \t1");
    println!("Data blocks:     \t{data_blocks}");
    println!("Data block size: \t{}", params.data_block_size);
    println!("Hash block size: \t{}", params.hash_block_size);
    println!("Hash algorithm:  \tsha256");
    println!("Salt:            \t{}", hex::encode(&params.salt));
    println!("Root hash:       \t{}", hex::encode(&out.root_hash));
    Ok(())
}

fn open(a: &VerityOpen) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    // The Verity table type locks both block sizes to 4096; a superblock
    // outside that can't be represented, so refuse rather than misload.
    if sb.data_block_size != 4096 || sb.hash_block_size != 4096 {
        bail!(
            "unsupported block sizes (data {}, hash {}); only 4096 is supported",
            sb.data_block_size,
            sb.hash_block_size
        );
    }
    let digest = hex::decode(&a.root_hash).context("parse root hash")?;

    let verity = Verity {
        data_dev: DevId::from_path(&a.data_dev).context("resolve data device")?,
        hash_dev: DevId::from_path(&a.hash_dev).context("resolve hash device")?,
        num_data_blocks: sb.data_blocks,
        algorithm: sb.algorithm,
        digest,
        salt: sb.salt,
    };
    let length = sb.data_blocks * u64::from(sb.data_block_size) / SECTOR;

    let control = Control::open().context("open /dev/mapper/control")?;
    let removed = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    removed
        .builder()
        .read_only()
        .add(0, length, verity)
        .context("build verity table")?
        .load()
        .context("load verity table")?;
    removed.resume().context("resume")?;
    let _ = Device::from(removed);
    Ok(())
}

fn close(a: &VerityClose) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?
        .0
        .remove()
        .context("remove")
}

fn verify(a: &VerityVerify) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    let params = VerityParams {
        data_block_size: sb.data_block_size,
        hash_block_size: sb.hash_block_size,
        salt: sb.salt,
        // The uuid never enters the hash-tree computation; only the salt
        // does. A zero uuid keeps the recomputed root hash correct.
        uuid: [0u8; 16],
    };
    let mut data =
        File::open(&a.data_dev).with_context(|| format!("open {}", a.data_dev.display()))?;
    let dbs = params.data_block_size as usize;
    let mut builder = VerityBuilder::new(&params).context("init verity builder")?;
    feed_from_reader(&mut data, &mut builder, dbs).context("hash data device")?;
    let computed = builder.finalize().root_hash;

    let expected = hex::decode(&a.root_hash).context("parse root hash")?;
    if expected == computed {
        println!("Verification successful.");
        Ok(())
    } else {
        bail!(
            "verification failed: computed root hash {} does not match {}",
            hex::encode(&computed),
            a.root_hash
        );
    }
}

fn dump(a: &VerityDump) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    println!("VERITY header information for {}", a.hash_dev.display());
    println!("UUID:            \t{}", format_uuid(&sb.uuid));
    println!("Hash type:       \t{}", sb.hash_type);
    println!("Data blocks:     \t{}", sb.data_blocks);
    println!("Data block size: \t{}", sb.data_block_size);
    println!("Hash block size: \t{}", sb.hash_block_size);
    println!("Hash algorithm:  \t{}", sb.algorithm);
    println!("Salt:            \t{}", hex::encode(&sb.salt));
    Ok(())
}

fn status(a: &VerityStatus) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    let (device, _) = control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?;
    if let Some(info) = device
        .target::<Verity>(0)
        .info()
        .context("read verity status")?
    {
        let state = if info.corrupted {
            "corrupted"
        } else {
            "verified"
        };
        println!("{}/{state} status: {info}", a.name);
    } else {
        println!("{}: no verity target at sector 0", a.name);
    }
    Ok(())
}

/// Format a 16-byte UUID in canonical 8-4-4-4-12 hyphenated form.
fn format_uuid(uuid: &[u8; 16]) -> String {
    let h = hex::encode(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Parse a UUID given as 32 hex chars or the canonical hyphenated form.
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(&stripped)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("uuid must be 16 bytes (32 hex digits)"))
}
