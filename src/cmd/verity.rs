// SPDX-License-Identifier: Apache-2.0

//! The `verity` persona — `veritysetup`-equivalent operations. Composes
//! the on-disk hash tree ([`devmap_verity`]) with a dm-verity table load
//! ([`devmap_linux`]).

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::{NonZeroU32, NonZeroU64};

use anyhow::{Context as _, Result, bail};
use devmap_linux::DevId;
use devmap_linux::targets::Verity;
use devmap_verity::{HashType, TreeWriter, Unverified, Verified};

use crate::cli::{
    VerityClose, VerityCmd, VerityDump, VerityFormat, VerityOpen, VerityStatus, VerityVerify,
};
use crate::{control, hex, size, urandom, uuid};

mod seek_sink;

use seek_sink::SeekSink;

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

/// Read the superblock from the start of a hash device.
fn read_superblock(hash_dev: &std::path::Path) -> Result<Verified> {
    let mut file = File::open(hash_dev).with_context(|| format!("open {}", hash_dev.display()))?;
    let mut bytes = Unverified::default();
    file.read_exact(bytes.as_mut())
        .with_context(|| format!("read superblock from {}", hash_dev.display()))?;
    let superblock = Verified::try_from(bytes)
        .with_context(|| format!("validate superblock from {}", hash_dev.display()))?;
    let padding = superblock.padding();
    let copied = std::io::copy(&mut file.take(padding), &mut std::io::sink())
        .with_context(|| format!("read superblock padding from {}", hash_dev.display()))?;
    if copied != padding {
        bail!("truncated superblock padding in {}", hash_dev.display());
    }
    Ok(superblock)
}

fn format(a: &VerityFormat) -> Result<()> {
    let salt_bytes = match &a.salt {
        Some(hexstr) => hex::decode(hexstr).context("parse --salt")?,
        None => urandom::bytes(32).context("read random salt")?,
    };
    let uuid_bytes = if let Some(s) = &a.uuid {
        uuid::parse(s).context("parse --uuid")?
    } else {
        let bytes = urandom::bytes(16).context("read random uuid")?;
        bytes.try_into().expect("urandom(16) is 16 bytes")
    };
    let mut data =
        File::open(&a.data_dev).with_context(|| format!("open {}", a.data_dev.display()))?;
    let size = size::of(&data).context("size data device")?;
    let data_block_size =
        NonZeroU32::new(a.data_block_size).context("invalid verity data block size")?;
    let data_blocks = NonZeroU64::new(size.div_ceil(u64::from(data_block_size.get())))
        .context("verity data device is empty")?;
    let builder = Verified::builder()
        .hash_type(HashType::Normal)
        .data_block_size(a.data_block_size)
        .context("invalid verity data block size")?
        .hash_block_size(a.hash_block_size)
        .context("invalid verity hash block size")?;
    let superblock = builder
        .salt(&salt_bytes)
        .context("set salt")?
        .build(uuid_bytes, data_blocks)
        .context("construct verity superblock")?;
    let mut hash = OpenOptions::new()
        .write(true)
        .open(&a.hash_dev)
        .with_context(|| format!("open {}", a.hash_dev.display()))?;
    hash.seek(SeekFrom::Start(a.hash_offset))
        .context("seek to hash tree offset")?;
    let bytes = Unverified::from(&superblock);
    std::io::Write::write_all(&mut hash, bytes.as_ref()).context("write verity superblock")?;
    std::io::copy(
        &mut std::io::repeat(0).take(superblock.padding()),
        &mut hash,
    )
    .context("write verity superblock padding")?;
    let root_hash = {
        let mut tree =
            TreeWriter::new(&mut hash, superblock).context("select verity hash implementation")?;
        std::io::copy(&mut data, &mut tree).context("hash data device")?;
        std::io::Write::flush(&mut tree).context("finish hash tree")?;
        tree.digest().context("read root digest")?.to_vec()
    };
    hash.sync_all().context("sync hash device")?;

    println!("VERITY header information for {}", a.hash_dev.display());
    println!("UUID:            \t{}", uuid::format(&uuid_bytes));
    println!("Hash type:       \t{}", HashType::Normal);
    println!("Data blocks:     \t{data_blocks}");
    println!("Data block size: \t{}", a.data_block_size);
    println!("Hash block size: \t{}", a.hash_block_size);
    println!("Hash algorithm:  \tsha256");
    println!("Salt:            \t{}", hex::encode(&salt_bytes));
    println!("Root hash:       \t{}", hex::encode(root_hash.as_ref()));
    Ok(())
}

fn open(a: &VerityOpen) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    if sb.hash_type() != HashType::Normal {
        bail!(
            "unsupported verity hash type {}; only normal (1) is supported",
            sb.hash_type()
        );
    }
    // The Verity table type locks both block sizes to 4096; a superblock
    // outside that can't be represented, so refuse rather than misload.
    let data_block_size = sb.data_block_size();
    let hash_block_size = sb.hash_block_size();
    if data_block_size != 4096 || hash_block_size != 4096 {
        bail!(
            "unsupported block sizes (data {data_block_size}, hash {hash_block_size}); only 4096 is supported"
        );
    }
    let digest = hex::decode(&a.root_hash).context("parse root hash")?;

    let verity = Verity {
        data_dev: DevId::from_path(&a.data_dev).context("resolve data device")?,
        hash_dev: DevId::from_path(&a.hash_dev).context("resolve hash device")?,
        num_data_blocks: sb.data_blocks().get(),
        algorithm: sb.algorithm().to_string(),
        digest,
        salt: sb.salt().to_vec(),
    };
    let length = sb.data_blocks().get() * u64::from(data_block_size) / size::SECTOR;

    let control = control::open()?;
    let device = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    device
        .builder()
        .read_only()
        .add(0, length, verity)
        .context("build verity table")?
        .load()
        .context("load verity table")?;
    device.resume().context("resume")?;
    Ok(())
}

fn close(a: &VerityClose) -> Result<()> {
    control::remove(&a.name)
}

fn verify(a: &VerityVerify) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    if sb.hash_type() != HashType::Normal {
        bail!(
            "unsupported verity hash type {}; only normal (1) is supported",
            sb.hash_type()
        );
    }
    let data = File::open(&a.data_dev).with_context(|| format!("open {}", a.data_dev.display()))?;
    let data_size = sb.data_blocks().get() * u64::from(sb.data_block_size());
    let mut data = data.take(data_size);
    let mut sink = SeekSink::default();
    let computed = {
        let mut tree =
            TreeWriter::new(&mut sink, sb).context("select verity hash implementation")?;
        std::io::copy(&mut data, &mut tree).context("hash data device")?;
        std::io::Write::flush(&mut tree).context("finish hash tree")?;
        tree.digest().context("read root digest")?.to_vec()
    };

    let expected = hex::decode(&a.root_hash).context("parse root hash")?;
    if expected.as_slice() == computed.as_slice() {
        println!("Verification successful.");
        Ok(())
    } else {
        bail!(
            "verification failed: computed root hash {} does not match {}",
            hex::encode(computed.as_ref()),
            a.root_hash
        );
    }
}

fn dump(a: &VerityDump) -> Result<()> {
    let sb = read_superblock(&a.hash_dev)?;
    println!("VERITY header information for {}", a.hash_dev.display());
    println!("UUID:            \t{}", uuid::format(sb.uuid()));
    println!("Hash type:       \t{}", sb.hash_type());
    println!("Data blocks:     \t{}", sb.data_blocks());
    println!("Data block size: \t{}", sb.data_block_size());
    println!("Hash block size: \t{}", sb.hash_block_size());
    println!("Hash algorithm:  \t{}", sb.algorithm());
    println!("Salt:            \t{}", hex::encode(sb.salt()));
    Ok(())
}

fn status(a: &VerityStatus) -> Result<()> {
    let device = control::by_name(&a.name)?;
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
