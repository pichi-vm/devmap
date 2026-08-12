// SPDX-License-Identifier: Apache-2.0

//! The `crypt` persona — `cryptsetup`-equivalent operations. Unlocks a
//! LUKS volume with [`devmap_luks`] and activates it as a dm-crypt mapping
//! via [`devmap_linux`], with no external tool.
//!
//! # How the master key reaches the kernel
//!
//! The key is never written into the dm-crypt table as hex. It goes into
//! the kernel keyring as a `logon` key — which userspace cannot read back —
//! and the table refers to it as `:<size>:logon:<description>`.
//!
//! dm-crypt copies the key into its own state when the table is loaded
//! (`set_key_user` does a `memcpy`) and never asks for it again, so the
//! keyring entry is deleted immediately afterwards. The mapping keeps
//! working, and the key is exposed for the shortest possible window.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use devmap_linux::targets::Crypt;
use devmap_linux::targets::crypt::{Key, KeyType};
use devmap_linux::{Control, DevId, Device};
use devmap_luks::{Header, MasterKey};
use keyutils::keytypes::{Logon, logon};

use crate::cli::{CryptClose, CryptCmd, CryptDump, CryptOpen, CryptStatus};

/// Bytes per sector — dm-crypt table offsets and lengths are in sectors.
const SECTOR: u64 = 512;

/// The logon-key subtype devmap publishes master keys under. Distinct from
/// cryptsetup's `cryptsetup:` so the two can never resolve to each other's
/// key for the same volume.
const KEY_SUBTYPE: &str = "devmap";

pub(crate) fn run(cmd: CryptCmd) -> Result<()> {
    match cmd {
        CryptCmd::Open(a) => open(&a),
        CryptCmd::Close(a) => close(&a),
        CryptCmd::Status(a) => status(&a),
        CryptCmd::Dump(a) => dump(&a),
    }
}

/// Read and parse the LUKS header at the start of `device`.
///
/// Only the header itself is read. The keyslot *areas* sit far beyond it —
/// megabytes in, for both versions — and are read on demand during
/// unlocking through the device handle instead of being slurped into
/// memory.
fn read_header(device: &Path) -> Result<Header> {
    let mut file = File::open(device).with_context(|| format!("open {}", device.display()))?;
    // 256 KiB comfortably covers a LUKS2 primary and secondary header at
    // the default 16 KiB hdr_size, and dwarfs LUKS1's 592-byte header.
    let mut raw = vec![0u8; 256 * 1024];
    let read = read_as_much_as_possible(&mut file, &mut raw)
        .with_context(|| format!("read header from {}", device.display()))?;
    raw.truncate(read);
    Header::parse(&raw).context("parse LUKS header")
}

/// Fill `buf` as far as the device allows, tolerating a short device.
fn read_as_much_as_possible(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// The passphrase, from a key file or an unechoed terminal prompt.
fn read_passphrase(key_file: Option<&Path>) -> Result<Vec<u8>> {
    match key_file {
        Some(path) => {
            let mut bytes =
                std::fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
            // A key file written by `echo` ends in a newline that was never
            // meant to be part of the passphrase.
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            Ok(bytes)
        }
        None => Ok(rpassword::prompt_password("Enter passphrase: ")
            .context("read passphrase")?
            .into_bytes()),
    }
}

/// The size of a block device or file, in bytes.
fn device_size(device: &Path) -> Result<u64> {
    let mut file = File::open(device).with_context(|| format!("open {}", device.display()))?;
    file.seek(SeekFrom::End(0))
        .with_context(|| format!("size {}", device.display()))
}

/// Publish `key` into the thread keyring as a `logon` key that dm-crypt can
/// look up, returning the handle so the caller can delete it again.
///
/// `logon` rather than `user` is the point: userspace cannot read a logon
/// key's payload back, so the master key is not recoverable from the
/// keyring even while it is there. The thread keyring is the narrowest
/// scope `request_key` searches, so nothing outside this thread sees it.
fn publish_key(volume_uuid: &str, key: &MasterKey) -> Result<keyutils::Key> {
    let mut ring = keyutils::Keyring::attach_or_create(keyutils::SpecialKeyring::Thread)
        .context("attach to the thread keyring")?;
    let description = logon::Description {
        subtype: KEY_SUBTYPE.into(),
        description: volume_uuid.to_owned().into(),
    };
    ring.add_key::<Logon, _, _>(&description, key.expose())
        .context("add the master key to the keyring")
}

fn open(a: &CryptOpen) -> Result<()> {
    let header = read_header(&a.device)?;
    let passphrase = read_passphrase(a.key_file.as_deref())?;
    // Keyslot areas are read straight off the device rather than buffered.
    let device_handle =
        File::open(&a.device).with_context(|| format!("open {}", a.device.display()))?;
    let master_key = header
        .unlock(&passphrase, &device_handle)
        .context("unlock the volume")?;

    let payload_offset = header.payload_offset_bytes().context("payload offset")?;
    let total = device_size(&a.device)?;
    if total <= payload_offset {
        bail!(
            "{} is {total} bytes, which leaves no payload after the {payload_offset}-byte header",
            a.device.display()
        );
    }
    let length_sectors = (total - payload_offset) / SECTOR;

    // The table refers to the key by `<subtype>:<description>`, which is how
    // the kernel renders a logon key's description.
    let description = format!("{KEY_SUBTYPE}:{}", header.uuid());
    let keyring_key = publish_key(header.uuid(), &master_key)?;
    drop(master_key);

    let sector_size = header.sector_size();
    let target = Crypt {
        iv_offset: header.iv_tweak(),
        offset: payload_offset / SECTOR,
        sector_size: (sector_size != 512).then_some(sector_size),
        allow_discards: a.allow_discards,
        ..Crypt::new(
            header.cipher_spec().context("cipher spec")?,
            Key::Keyring {
                size: header.key_bytes(),
                kind: KeyType::Logon,
                description,
            },
            DevId::from_path(&a.device).context("resolve backing device")?,
        )
    };

    let activated = activate(&a.name, length_sectors, target);

    // dm-crypt copied the key at table load and never asks again, so the
    // keyring entry is dead weight now — remove it whether or not the
    // activation succeeded.
    if let Err(e) = keyring_key.invalidate() {
        eprintln!("devmap: warning: could not remove the keyring key: {e}");
    }
    activated
}

/// Create, load, and resume the mapping.
fn activate(name: &str, length_sectors: u64, target: Crypt) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    let removed = control
        .create(name)
        .with_context(|| format!("create {name}"))?;
    removed
        .builder()
        .add(0, length_sectors, target)
        .context("build the dm-crypt table")?
        .load()
        .context("load the dm-crypt table")?;
    removed.resume().context("resume")?;
    let _ = Device::from(removed);
    Ok(())
}

fn close(a: &CryptClose) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?
        .0
        .remove()
        .context("remove")
}

fn status(a: &CryptStatus) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    let (device, status) = control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?;
    let id = device.id();
    println!("{}", a.name);
    println!("  type:    dm-crypt");
    println!(
        "  state:   {}",
        if status.is_suspended() {
            "suspended"
        } else {
            "active"
        }
    );
    println!("  device:  {}:{}", id.major(), id.minor());
    // The table carries the key reference; print only the non-secret parts.
    for row in device.table().context("read table")? {
        if let Some(table) = row.parse::<Crypt>() {
            println!("  cipher:  {}", table.cipher);
            println!("  offset:  {} sectors", table.offset);
            println!("  keyring: {}", key_reference(&table.key));
        }
    }
    Ok(())
}

/// Describe a table's key without ever revealing key bytes.
fn key_reference(key: &Key) -> String {
    match key {
        Key::Keyring {
            size,
            kind,
            description,
        } => format!("{kind}:{description} ({size} bytes)"),
        Key::Hex(bytes) => format!("<{} bytes in the table>", bytes.len()),
        Key::Absent => "<none>".to_owned(),
    }
}

fn dump(a: &CryptDump) -> Result<()> {
    let header = read_header(&a.device)?;
    println!("LUKS header information for {}", a.device.display());
    println!("Version:        \t{}", header.version());
    println!("UUID:           \t{}", header.uuid());
    println!(
        "Cipher:         \t{}",
        header.cipher_spec().context("cipher spec")?
    );
    println!("MK bits:        \t{}", header.key_bytes() * 8);
    println!(
        "Payload offset: \t{} sectors",
        header.payload_offset_bytes().context("payload offset")? / SECTOR
    );
    println!("Sector size:    \t{}", header.sector_size());
    for slot in header.keyslot_summaries() {
        println!("Keyslot {}:", slot.index);
        println!("  KDF:          \t{}", slot.kdf);
        println!("  Iterations:   \t{}", slot.iterations);
        if slot.memory_kib > 0 {
            println!("  Memory:       \t{} KiB", slot.memory_kib);
            println!("  Threads:      \t{}", slot.lanes);
        }
        println!("  AF stripes:   \t{}", slot.stripes);
    }
    Ok(())
}
