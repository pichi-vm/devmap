// SPDX-License-Identifier: Apache-2.0

//! The `devmap` command tree. Noun-first: `devmap <object> <verb>`. The
//! multi-call shim in [`crate::multicall`] maps legacy tool names
//! (`dmsetup`, …) onto these objects.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "devmap", version, about = "A device-mapper multitool")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) object: Object,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Object {
    /// Raw device-mapper operations — the `dmsetup` layer.
    #[command(subcommand)]
    Dm(DmCmd),
    /// dm-verity volumes — the `veritysetup` layer.
    #[command(subcommand)]
    Verity(VerityCmd),
    /// dm-zoned volumes — the `dmzadm` layer.
    #[command(subcommand)]
    Zoned(ZonedCmd),
    /// dm-integrity volumes — the `integritysetup` layer.
    #[command(subcommand)]
    Integrity(IntegrityCmd),
    /// LUKS encrypted volumes — the `cryptsetup` layer.
    #[command(subcommand)]
    Crypt(CryptCmd),
    /// dm-snapshot persistent COW images.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),
    /// Create the legacy-tool symlinks (dmsetup, veritysetup, …) in a directory.
    InstallLinks(InstallLinks),
}

/// The `dmsetup`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum DmCmd {
    /// Create a device, load a table, and resume it.
    Create(Create),
    /// Stage a new inactive table without activating it.
    Reload(Reload),
    /// Remove a device.
    Remove(Name),
    /// Suspend a device (flush and queue I/O).
    Suspend(Name),
    /// Resume a device, activating any staged table.
    Resume(Name),
    /// Discard a staged inactive table.
    Clear(Name),
    /// Print the active table (`STATUSTYPE_TABLE`).
    Table(Name),
    /// Print runtime status (`STATUSTYPE_INFO`).
    Status(Name),
    /// Print device information (state, counts, dev_t).
    Info(Name),
    /// List all device-mapper devices.
    Ls,
    /// Print the devices a table depends on.
    Deps(Name),
    /// Rename a device, or set its uuid with `--setuuid`.
    Rename(Rename),
    /// Send a message to a target.
    Message(Message),
    /// Block until the device's event counter advances.
    Wait(Wait),
    /// List the target types the kernel supports.
    Targets,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Create {
    /// Device name.
    pub(crate) name: String,
    /// Table file, or `-`/omitted for stdin.
    #[arg(long)]
    pub(crate) table: Option<PathBuf>,
    /// Attach this uuid to the new device.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
    /// Load the table read-only.
    #[arg(long)]
    pub(crate) readonly: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Reload {
    /// Device name.
    pub(crate) name: String,
    /// Table file, or `-`/omitted for stdin.
    #[arg(long)]
    pub(crate) table: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Name {
    /// Device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Rename {
    /// Current device name.
    pub(crate) name: String,
    /// New name, or new uuid with `--setuuid`.
    pub(crate) new_name: String,
    /// Interpret `new_name` as a uuid to attach, not a new name.
    #[arg(long)]
    pub(crate) setuuid: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Message {
    /// Device name.
    pub(crate) name: String,
    /// Sector the message targets (0 for whole-device targets).
    pub(crate) sector: u64,
    /// The message words, e.g. `create_thin 0`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub(crate) words: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Wait {
    /// Device name.
    pub(crate) name: String,
    /// Wait for an event after this number; defaults to the current one.
    pub(crate) event_nr: Option<u32>,
}

/// The `veritysetup`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum VerityCmd {
    /// Build a hash tree over a data device and write it to a hash device.
    Format(VerityFormat),
    /// Activate a verity device from a data device, hash device, and root hash.
    Open(VerityOpen),
    /// Deactivate a verity device.
    Close(VerityClose),
    /// Recompute the root hash from the data device and compare it.
    Verify(VerityVerify),
    /// Print a hash device's superblock fields.
    Dump(VerityDump),
    /// Print a verity device's runtime status.
    Status(VerityStatus),
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityFormat {
    /// Data device to protect.
    pub(crate) data_dev: PathBuf,
    /// Hash device to write the tree to.
    pub(crate) hash_dev: PathBuf,
    /// Data block size in bytes.
    #[arg(long, default_value_t = 4096)]
    pub(crate) data_block_size: u32,
    /// Hash block size in bytes.
    #[arg(long, default_value_t = 4096)]
    pub(crate) hash_block_size: u32,
    /// Salt as hex; defaults to 32 random bytes.
    #[arg(long)]
    pub(crate) salt: Option<String>,
    /// UUID (hex or hyphenated); defaults to random.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
    /// Byte offset of the superblock on the hash device.
    #[arg(long, default_value_t = 0)]
    pub(crate) hash_offset: u64,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityOpen {
    /// Data device.
    pub(crate) data_dev: PathBuf,
    /// Name for the new mapped device.
    pub(crate) name: String,
    /// Hash device.
    pub(crate) hash_dev: PathBuf,
    /// Expected root hash (hex).
    pub(crate) root_hash: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityClose {
    /// Mapped device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityVerify {
    /// Data device.
    pub(crate) data_dev: PathBuf,
    /// Hash device.
    pub(crate) hash_dev: PathBuf,
    /// Expected root hash (hex).
    pub(crate) root_hash: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityDump {
    /// Hash device.
    pub(crate) hash_dev: PathBuf,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerityStatus {
    /// Mapped device name.
    pub(crate) name: String,
}

/// The `dmzadm`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum ZonedCmd {
    /// Write dm-zoned metadata to a zoned block device.
    Format(ZonedFormat),
    /// Validate a zoned device's superblock.
    Check(ZonedCheck),
    /// Activate a dm-zoned device over a formatted zoned device.
    Start(ZonedStart),
    /// Deactivate a dm-zoned device.
    Stop(ZonedStop),
    /// Print a dm-zoned device's runtime status.
    Status(ZonedStatus),
}

#[derive(clap::Args, Debug)]
pub(crate) struct ZonedFormat {
    /// Zoned block device to format.
    pub(crate) device: PathBuf,
    /// Volume label (truncated to 32 bytes).
    #[arg(long)]
    pub(crate) label: Option<String>,
    /// Sequential zones to reserve for reclaim; defaults to a proportional value.
    #[arg(long)]
    pub(crate) seq: Option<u32>,
    /// Volume UUID (hex or hyphenated); defaults to random.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
    /// Device UUID (hex or hyphenated); defaults to random.
    #[arg(long)]
    pub(crate) dev_uuid: Option<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ZonedCheck {
    /// Zoned block device.
    pub(crate) device: PathBuf,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ZonedStart {
    /// Formatted zoned block device.
    pub(crate) device: PathBuf,
    /// Name for the mapped device; defaults to `dmz-<basename>`.
    pub(crate) name: Option<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ZonedStop {
    /// Mapped device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ZonedStatus {
    /// Mapped device name.
    pub(crate) name: String,
}

/// The `integritysetup`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum IntegrityCmd {
    /// Write a dm-integrity superblock sized to the device.
    Format(IntegrityFormat),
    /// Activate an integrity device over a formatted device.
    Open(IntegrityOpen),
    /// Deactivate an integrity device.
    Close(IntegrityClose),
    /// Print an integrity device's runtime status.
    Status(IntegrityStatus),
}

/// Shared knobs for `format` and `open`; they MUST match, so the same
/// fields appear on both (integritysetup takes them on both too).
#[derive(clap::Args, Debug)]
pub(crate) struct IntegrityFormat {
    /// Device to protect.
    pub(crate) device: PathBuf,
    /// Internal hash / checksum algorithm.
    #[arg(long, default_value = "crc32c")]
    pub(crate) integrity: String,
    /// Per-block tag size in bytes; omitted lets the kernel derive it.
    #[arg(long)]
    pub(crate) tag_size: Option<u32>,
    /// Allow discards to pass through.
    #[arg(long)]
    pub(crate) allow_discards: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct IntegrityOpen {
    /// Formatted device.
    pub(crate) device: PathBuf,
    /// Name for the mapped device.
    pub(crate) name: String,
    /// Internal hash / checksum algorithm (must match format).
    #[arg(long, default_value = "crc32c")]
    pub(crate) integrity: String,
    /// Per-block tag size in bytes (must match format).
    #[arg(long)]
    pub(crate) tag_size: Option<u32>,
    /// Allow discards to pass through.
    #[arg(long)]
    pub(crate) allow_discards: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct IntegrityClose {
    /// Mapped device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct IntegrityStatus {
    /// Mapped device name.
    pub(crate) name: String,
}

/// The `cryptsetup`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum CryptCmd {
    /// Unlock a LUKS volume and activate it as a dm-crypt device.
    Open(CryptOpen),
    /// Deactivate a dm-crypt device.
    Close(CryptClose),
    /// Print a mapped device's state (never key material).
    Status(CryptStatus),
    /// Print a LUKS header's fields (never key material).
    Dump(CryptDump),
}

#[derive(clap::Args, Debug)]
pub(crate) struct CryptOpen {
    /// The LUKS volume.
    pub(crate) device: PathBuf,
    /// Name for the mapped device under /dev/mapper.
    pub(crate) name: String,
    /// Read the passphrase from this file instead of prompting.
    #[arg(long)]
    pub(crate) key_file: Option<PathBuf>,
    /// Allow discards (TRIM) to pass through to the backing device.
    ///
    /// This can leak which blocks are unused, so it is off by default.
    #[arg(long)]
    pub(crate) allow_discards: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CryptClose {
    /// Mapped device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CryptStatus {
    /// Mapped device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CryptDump {
    /// The LUKS volume.
    pub(crate) device: PathBuf,
}

/// The dm-snapshot COW verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum SnapshotCmd {
    /// Write a raw image into a dm-snapshot persistent COW.
    Convert(SnapshotConvert),
}

#[derive(clap::Args, Debug)]
pub(crate) struct SnapshotConvert {
    /// Raw source image (all-zero chunks are skipped, layering over a zero origin).
    pub(crate) raw: PathBuf,
    /// COW output — a file (truncated) or a block device (written in place).
    pub(crate) cow: PathBuf,
    /// COW chunk size in 512-byte sectors (power of two, >= 8).
    #[arg(long, default_value_t = devmap_snapshot::DEFAULT_CHUNK_SIZE_SECTORS)]
    pub(crate) chunk_size: u32,
}

#[derive(clap::Args, Debug)]
pub(crate) struct InstallLinks {
    /// Directory to create the symlinks in (e.g. `/usr/local/bin`).
    pub(crate) dir: PathBuf,
    /// Replace any existing files at those names.
    #[arg(long)]
    pub(crate) force: bool,
}
