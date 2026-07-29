// SPDX-License-Identifier: Apache-2.0

//! [`Target`]: the "trivial" dm target types, as a closed enum with an
//! `Other` catch-all. [`TableLine`]: one `<start> <length> <target>` row.
//! `DmTableBuf`: the kernel-ABI byte buffer for `DM_TABLE_LOAD`.
//! `TableStatusIter`: parses `DM_TABLE_STATUS`'s response back into
//! `TableLine`s.

use std::fmt;

use zerocopy::IntoBytes;

use crate::Error;
use crate::device::DevId;
use crate::header::DmHeader;
use crate::uapi::{DM_MAX_TYPE_NAME, DM_TARGET_SPEC_SIZE, dm_target_spec_raw};

/// One of the "trivial" (plain-text, no external deps, no
/// security-sensitive fields) real Linux device-mapper target types, plus
/// a catch-all for anything else. A closed enum rather than a trait: the
/// kernel can report target types this crate has no specific variant for
/// (created by LVM, cryptsetup, a newer kernel, ...) when reading status
/// back, and that must be representable without failing — `Other` is
/// that representation, used both for unrecognized reads and for
/// deliberately writing a custom/unimplemented target type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Target {
    /// Discards writes, returns zeroed reads. No parameters.
    Zero,
    /// Maps straight through to another device at a sector offset.
    Linear { device: DevId, offset_sectors: u64 },
    /// Returns I/O errors for the whole range. No parameters.
    ErrorTarget,
    /// Marks a device as the origin of a snapshot.
    SnapshotOrigin { origin: DevId },
    /// A copy-on-write snapshot. Always written as persistent with
    /// overflow support ("PO"), matching established production usage
    /// (carapace-dm's own hardcoded choice) rather than exposing every
    /// possible persistence-flag combination.
    Snapshot { origin: DevId, cow: DevId, chunk_size_sectors: u64 },
    /// Concatenates several devices into one striped range.
    Striped { chunk_size_sectors: u64, stripes: Vec<(DevId, u64)> },
    /// dm-verity. `digest`/`salt` are raw bytes, hex-encoded on write.
    /// Data/hash block size is locked to 4096 and `hash_start_block` to 1,
    /// matching carapace-dm's own validated defaults rather than exposing
    /// every option the kernel target supports.
    #[non_exhaustive]
    Verity {
        data_dev: DevId,
        hash_dev: DevId,
        num_data_blocks: u64,
        algorithm: String,
        digest: Vec<u8>,
        salt: Vec<u8>,
    },
    /// Delays (and optionally splits) I/O by device class. `write`/`flush`
    /// use `read`'s values when unset but a sibling leg is present (e.g.
    /// `flush: Some(_)` with `write: None` renders the write leg using
    /// `read`) — matching the kernel's 3/6/9-argument table forms, where
    /// the 9-argument form always carries all three legs explicitly.
    Delay { read: DelayLeg, write: Option<DelayLeg>, flush: Option<DelayLeg> },
    /// Exposes one stripe of an existing striped/RAID0 mapping as its own
    /// device, for per-stripe `QoS` isolation.
    Unstriped { stripes: u32, chunk_size_sectors: u64, stripe_index: u32, device: DevId, offset_sectors: u64 },
    /// Injects read/write errors at specific blocks, for fault-injection
    /// testing. Bad-block management (`addbadblock`/etc.) is message-driven
    /// — see [`crate::Device::message`].
    Dust { device: DevId, offset_sectors: u64, block_size: u32 },
    /// Tracks which blocks of `origin` have changed since which "era",
    /// for incremental backup. Era rollover/snapshot control is
    /// message-driven — see [`crate::Device::message`].
    Era { metadata: DevId, origin: DevId, block_size: u32 },
    /// Logs every write to `device` into `log_device`, for crash-consistency
    /// testing with an external replay tool. Marking points in the log is
    /// message-driven — see [`crate::Device::message`].
    LogWrites { device: DevId, log_device: DevId },
    /// Merges an existing persistent [`Target::Snapshot`]'s COW data back
    /// into its origin. Same table shape as `Snapshot`, always written as
    /// persistent ("PO") to match.
    ///
    /// Handover procedure (verified against `dm-snap.c`'s
    /// `snapshot_preresume`/`snapshot_resume` and against a real kernel):
    /// with `origin` currently carrying a [`Target::SnapshotOrigin`]
    /// mapping and `snap` currently carrying the `Target::Snapshot`
    /// mapping sharing this `cow` device,
    /// 1. [`crate::Device::suspend`] `origin`,
    /// 2. [`crate::Device::load_table`] `origin` with this
    ///    `Target::SnapshotMerge`,
    /// 3. [`crate::Device::suspend`] `snap` — the kernel refuses to
    ///    resume a `snapshot-merge` target with `EINVAL` unless the
    ///    `snapshot` device sharing its COW device is already suspended,
    /// 4. [`crate::Device::resume`] `origin` — this both hands over the
    ///    COW exception table and starts the (background) merge.
    ///
    /// `snap` returns `EIO` on access from this point on and should be
    /// removed once merging completes (poll `origin`'s
    /// [`crate::Device::table_status`] until `sectors_allocated` equals
    /// `metadata_sectors`).
    SnapshotMerge { origin: DevId, cow: DevId, chunk_size_sectors: u64 },
    /// Exposes a zoned block device (ZBC/ZAC/ZNS) as a regular block
    /// device. `device` must already be formatted with the kernel's
    /// zoned-device metadata (via an external tool) before first use.
    Zoned { device: DevId },
    /// Injects configurable faults (I/O errors, silent data corruption)
    /// into a normally-behaving device, for fault-injection testing.
    Flakey { device: DevId, offset_sectors: u64, up_interval_secs: u32, down_interval_secs: u32, features: Vec<FlakeyFeature> },
    /// A small fast device caching writes for a slower origin device.
    /// Only `high_watermark`/`low_watermark` are exposed; the rest of the
    /// kernel target's ~15 optional arguments are locked to their
    /// defaults, matching this crate's existing precedent (e.g.
    /// `Target::Verity`'s locked block size).
    #[non_exhaustive]
    Writecache {
        kind: WritecacheKind,
        origin: DevId,
        cache: DevId,
        block_size: u32,
        high_watermark_percent: Option<u32>,
        low_watermark_percent: Option<u32>,
    },
    /// Adds per-block integrity tags to `device`, detecting silent data
    /// corruption. Only `internal_hash`/`allow_discards` are exposed; the
    /// journal/crypto/bitmap-tuning arguments are locked out — this
    /// target's first-use superblock formatting dance (zero the
    /// superblock, load once to let the kernel format it, reload with the
    /// real size) is the caller's responsibility using
    /// [`crate::Device::load_table`], not something this crate automates.
    #[non_exhaustive]
    Integrity {
        device: DevId,
        reserved_sectors: u64,
        tag_size: Option<u32>,
        mode: IntegrityMode,
        internal_hash: Option<String>,
        allow_discards: bool,
    },
    /// Software RAID, bridging to the kernel's MD raid personalities.
    /// Only the mandatory `chunk_size` raid parameter is exposed; sync
    /// control, rebuild indices, and journal devices are locked out
    /// (available via [`crate::Device::message`] for sync control, or
    /// `Target::Other` for anything more exotic).
    Raid { raid_type: RaidType, chunk_size_sectors: u64, devices: Vec<RaidDevicePair> },
    /// A thin-provisioning pool backing zero or more [`Target::Thin`]
    /// devices. Provisioning (`create_thin`/`create_snap`/`delete`) is
    /// message-driven — see [`crate::Device::message`].
    #[non_exhaustive]
    ThinPool {
        metadata: DevId,
        data: DevId,
        data_block_size_sectors: u64,
        low_water_mark_blocks: u64,
        skip_block_zeroing: bool,
        ignore_discard: bool,
        no_discard_passdown: bool,
        read_only: bool,
        error_if_no_space: bool,
    },
    /// One provisioned volume inside a [`Target::ThinPool`]. `dev_id` must
    /// already exist in the pool (created via a `create_thin`/`create_snap`
    /// message — see [`crate::Device::message`]) before this table line
    /// can be loaded.
    Thin { pool: DevId, dev_id: u32, external_origin: Option<DevId> },
    /// Any target type this enum has no specific variant for — either
    /// encountered while reading (an unrecognized `kernel_type_name`), or
    /// deliberately constructed to write a custom/unimplemented target.
    Other { kernel_type_name: Vec<u8>, params: String },
}

/// One `(metadata device, data device)` pair of a [`Target::Raid`]
/// mapping. `metadata` of `None` renders as `-` (no dedicated metadata
/// device for that slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RaidDevicePair {
    pub metadata: Option<DevId>,
    pub data: DevId,
}

impl RaidDevicePair {
    /// A pair with a dedicated metadata device.
    pub fn new(metadata: Option<DevId>, data: DevId) -> Self {
        Self { metadata, data }
    }

    /// A pair with no dedicated metadata device (renders `-` for metadata).
    pub fn data_only(data: DevId) -> Self {
        Self { metadata: None, data }
    }
}

/// One `<device, offset, delay>` leg of a [`Target::Delay`] mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DelayLeg {
    pub device: DevId,
    pub offset_sectors: u64,
    pub delay_ms: u32,
}

impl DelayLeg {
    /// A delay leg: route I/O to `device` at `offset_sectors`, delayed by
    /// `delay_ms` milliseconds.
    pub fn new(device: DevId, offset_sectors: u64, delay_ms: u32) -> Self {
        Self { device, offset_sectors, delay_ms }
    }
}

/// Which I/O direction a [`FlakeyFeature::CorruptBioByte`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FlakeyDirection {
    Read,
    Write,
}

/// One feature flag of a [`Target::Flakey`] mapping. A closed set: the
/// kernel target supports exactly these six, no more.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FlakeyFeature {
    /// Fail all reads during the down interval.
    ErrorReads,
    /// Silently discard writes during the down interval.
    DropWrites,
    /// Fail all writes during the down interval.
    ErrorWrites,
    /// Overwrite one byte of matching bios during the down interval.
    CorruptBioByte { nth_byte: u32, direction: FlakeyDirection, value: u8, flags: u32 },
    /// Randomly corrupt a byte in read bios. `probability` is out of 100.
    RandomReadCorrupt { probability: u32 },
    /// Randomly corrupt a byte in write bios. `probability` is out of 100.
    RandomWriteCorrupt { probability: u32 },
}

/// Backing store kind for a [`Target::Writecache`] cache device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WritecacheKind {
    /// A regular block device (SSD).
    Ssd,
    /// Persistent memory (DAX).
    PersistentMemory,
}

/// [`Target::Integrity`]'s write mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IntegrityMode {
    /// Direct writes, no journal.
    Direct,
    /// Journaled writes.
    Journaled,
    /// Bitmap mode.
    Bitmap,
    /// Recovery mode.
    Recovery,
    /// Inline mode: tags stored in the underlying device's own integrity
    /// profile.
    Inline,
}

/// [`Target::Raid`]'s raid level. Default layouts only — the kernel's
/// `_la`/`_ra`/`_ls`/`_rs`/`_n` layout-suffix variants for raid5/6 are not
/// exposed; use `Target::Other` for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RaidType {
    Raid0,
    Raid1,
    Raid4,
    Raid5,
    Raid6,
    Raid10,
}

fn write_hex_lower<W: fmt::Write + ?Sized>(w: &mut W, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(w, "{b:02x}")?;
    }
    Ok(())
}

/// Data/hash block size locked to 4096 for [`Target::Verity`], matching
/// carapace-dm's validated default rather than exposing every value the
/// kernel target supports.
const VERITY_BLOCK_SIZE: u32 = 4096;

impl Target {
    /// The kernel's name for this target type, as written into
    /// `dm_target_spec.target_type`.
    pub fn name(&self) -> &[u8] {
        match self {
            Target::Zero => b"zero",
            Target::Linear { .. } => b"linear",
            Target::ErrorTarget => b"error",
            Target::SnapshotOrigin { .. } => b"snapshot-origin",
            Target::Snapshot { .. } => b"snapshot",
            Target::Striped { .. } => b"striped",
            Target::Verity { .. } => b"verity",
            Target::Delay { .. } => b"delay",
            Target::Unstriped { .. } => b"unstriped",
            Target::Dust { .. } => b"dust",
            Target::Era { .. } => b"era",
            Target::LogWrites { .. } => b"log-writes",
            Target::SnapshotMerge { .. } => b"snapshot-merge",
            Target::Zoned { .. } => b"zoned",
            Target::Flakey { .. } => b"flakey",
            Target::Writecache { .. } => b"writecache",
            Target::Integrity { .. } => b"integrity",
            Target::Raid { .. } => b"raid",
            Target::ThinPool { .. } => b"thin-pool",
            Target::Thin { .. } => b"thin",
            Target::Other { kernel_type_name, .. } => kernel_type_name,
        }
    }

    /// Write this target's kernel-ABI parameter string.
    #[allow(clippy::too_many_lines)] // one match arm per Target variant; splitting would obscure the 1:1 mapping
    pub fn params(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        match self {
            Target::Zero | Target::ErrorTarget => Ok(()),
            Target::Linear { device, offset_sectors } => {
                write!(w, "{device} {offset_sectors}")
            }
            Target::SnapshotOrigin { origin: dev } | Target::Zoned { device: dev } => {
                write!(w, "{dev}")
            }
            Target::Snapshot { origin, cow, chunk_size_sectors }
            | Target::SnapshotMerge { origin, cow, chunk_size_sectors } => {
                write!(w, "{origin} {cow} PO {chunk_size_sectors}")
            }
            Target::Striped { chunk_size_sectors, stripes } => {
                write!(w, "{} {chunk_size_sectors}", stripes.len())?;
                for (device, offset) in stripes {
                    write!(w, " {device} {offset}")?;
                }
                Ok(())
            }
            Target::Verity { data_dev, hash_dev, num_data_blocks, algorithm, digest, salt } => {
                write!(
                    w,
                    "1 {data_dev} {hash_dev} {VERITY_BLOCK_SIZE} {VERITY_BLOCK_SIZE} {num_data_blocks} 1 {algorithm} ",
                )?;
                write_hex_lower(w, digest)?;
                w.write_char(' ')?;
                write_hex_lower(w, salt)
            }
            Target::Delay { read, write, flush } => {
                write!(w, "{} {} {}", read.device, read.offset_sectors, read.delay_ms)?;
                if write.is_some() || flush.is_some() {
                    let leg = write.unwrap_or(*read);
                    write!(w, " {} {} {}", leg.device, leg.offset_sectors, leg.delay_ms)?;
                }
                if let Some(leg) = flush {
                    write!(w, " {} {} {}", leg.device, leg.offset_sectors, leg.delay_ms)?;
                }
                Ok(())
            }
            Target::Unstriped { stripes, chunk_size_sectors, stripe_index, device, offset_sectors } => {
                write!(w, "{stripes} {chunk_size_sectors} {stripe_index} {device} {offset_sectors}")
            }
            Target::Dust { device, offset_sectors, block_size } => {
                write!(w, "{device} {offset_sectors} {block_size}")
            }
            Target::Era { metadata, origin, block_size } => {
                write!(w, "{metadata} {origin} {block_size}")
            }
            Target::LogWrites { device, log_device } => {
                write!(w, "{device} {log_device}")
            }
            Target::Flakey { device, offset_sectors, up_interval_secs, down_interval_secs, features } => {
                write!(w, "{device} {offset_sectors} {up_interval_secs} {down_interval_secs}")?;
                let token_count: u32 = features.iter().map(flakey_feature_token_count).sum();
                write!(w, " {token_count}")?;
                for feature in features {
                    write_flakey_feature(w, feature)?;
                }
                Ok(())
            }
            Target::Writecache {
                kind,
                origin,
                cache,
                block_size,
                high_watermark_percent,
                low_watermark_percent,
            } => {
                let kind = match kind {
                    WritecacheKind::Ssd => 's',
                    WritecacheKind::PersistentMemory => 'p',
                };
                write!(w, "{kind} {origin} {cache} {block_size}")?;
                let opt_count = 2 * (u32::from(high_watermark_percent.is_some()) + u32::from(low_watermark_percent.is_some()));
                write!(w, " {opt_count}")?;
                if let Some(hw) = high_watermark_percent {
                    write!(w, " high_watermark {hw}")?;
                }
                if let Some(lw) = low_watermark_percent {
                    write!(w, " low_watermark {lw}")?;
                }
                Ok(())
            }
            Target::Integrity { device, reserved_sectors, tag_size, mode, internal_hash, allow_discards } => {
                let mode = match mode {
                    IntegrityMode::Direct => 'D',
                    IntegrityMode::Journaled => 'J',
                    IntegrityMode::Bitmap => 'B',
                    IntegrityMode::Recovery => 'R',
                    IntegrityMode::Inline => 'I',
                };
                write!(w, "{device} {reserved_sectors} ")?;
                match tag_size {
                    Some(size) => write!(w, "{size}")?,
                    None => w.write_char('-')?,
                }
                write!(w, " {mode}")?;
                let opt_count = u32::from(internal_hash.is_some()) + u32::from(*allow_discards);
                write!(w, " {opt_count}")?;
                if let Some(alg) = internal_hash {
                    write!(w, " internal_hash:{alg}")?;
                }
                if *allow_discards {
                    write!(w, " allow_discards")?;
                }
                Ok(())
            }
            Target::Raid { raid_type, chunk_size_sectors, devices } => {
                let raid_type = match raid_type {
                    RaidType::Raid0 => "raid0",
                    RaidType::Raid1 => "raid1",
                    RaidType::Raid4 => "raid4",
                    RaidType::Raid5 => "raid5",
                    RaidType::Raid6 => "raid6",
                    RaidType::Raid10 => "raid10",
                };
                // `<chunk_size>` is a bare positional number, not a
                // `chunk_size <value>` keyword pair — confirmed against
                // dm-raid.c's `parse_raid_params`, which reads the first
                // raid_param straight through `kstrtoint`. `#raid_params`
                // is therefore 1, covering just this one value.
                write!(w, "{raid_type} 1 {chunk_size_sectors} {}", devices.len())?;
                for pair in devices {
                    match pair.metadata {
                        Some(metadata) => write!(w, " {metadata}")?,
                        None => w.write_str(" -")?,
                    }
                    write!(w, " {}", pair.data)?;
                }
                Ok(())
            }
            Target::ThinPool {
                metadata,
                data,
                data_block_size_sectors,
                low_water_mark_blocks,
                skip_block_zeroing,
                ignore_discard,
                no_discard_passdown,
                read_only,
                error_if_no_space,
            } => {
                write!(w, "{metadata} {data} {data_block_size_sectors} {low_water_mark_blocks}")?;
                let flags: [(bool, &str); 5] = [
                    (*skip_block_zeroing, "skip_block_zeroing"),
                    (*ignore_discard, "ignore_discard"),
                    (*no_discard_passdown, "no_discard_passdown"),
                    (*read_only, "read_only"),
                    (*error_if_no_space, "error_if_no_space"),
                ];
                let count = flags.iter().filter(|(set, _)| *set).count();
                write!(w, " {count}")?;
                for (set, name) in flags {
                    if set {
                        write!(w, " {name}")?;
                    }
                }
                Ok(())
            }
            Target::Thin { pool, dev_id, external_origin } => {
                write!(w, "{pool} {dev_id}")?;
                if let Some(external_origin) = external_origin {
                    write!(w, " {external_origin}")?;
                }
                Ok(())
            }
            Target::Other { params, .. } => w.write_str(params),
        }
    }

    /// Parse a `(kernel_type_name, params)` pair as reported by the
    /// kernel (e.g. via `DM_TABLE_STATUS`) into a `Target`. Infallible —
    /// anything not specifically recognized becomes `Target::Other`.
    ///
    /// Only target types whose *status* output actually matches their
    /// *creation* parameter shape are reconstructed into a typed variant
    /// here: `zero`/`error` report no status at all, `linear`/
    /// `snapshot-origin` echo their creation params verbatim. `snapshot`,
    /// `verity`, and `striped` all report fundamentally different
    /// information at status time (allocation/health data, not the
    /// original construction parameters) — reconstructing a
    /// `Target::Verity`/`Target::Snapshot`/`Target::Striped` from their
    /// status strings would silently produce wrong data, so those fall
    /// through to `Other` even though this crate knows how to *write*
    /// them.
    pub fn from_status(kernel_type_name: &[u8], params: &str) -> Target {
        match kernel_type_name {
            b"zero" if params.is_empty() => Target::Zero,
            b"error" if params.is_empty() => Target::ErrorTarget,
            b"linear" => parse_linear(params).unwrap_or_else(|| Self::other(kernel_type_name, params)),
            b"snapshot-origin" => {
                parse_snapshot_origin(params).unwrap_or_else(|| Self::other(kernel_type_name, params))
            }
            _ => Self::other(kernel_type_name, params),
        }
    }

    fn other(kernel_type_name: &[u8], params: &str) -> Target {
        Target::Other { kernel_type_name: kernel_type_name.to_vec(), params: params.to_string() }
    }

    /// Reject targets this crate can render but the kernel would refuse at
    /// `DM_TABLE_LOAD`, catching them at build time with an actionable
    /// [`Error::Usage`] rather than an opaque `EINVAL` from the ioctl.
    ///
    /// Currently just [`Target::ThinPool`]: dm-thin's `parse_pool_features`
    /// declares `_args = {{0, 4, ...}}` and rejects any feature-flag count
    /// outside `[0, 4]` before it even inspects the keywords — so a pool
    /// with all five flags set (which `params` would render as `... 5 ...`)
    /// is rejected by the kernel regardless.
    fn validate(&self) -> Result<(), Error> {
        if let Target::ThinPool {
            skip_block_zeroing,
            ignore_discard,
            no_discard_passdown,
            read_only,
            error_if_no_space,
            ..
        } = self
        {
            let set = u32::from(*skip_block_zeroing)
                + u32::from(*ignore_discard)
                + u32::from(*no_discard_passdown)
                + u32::from(*read_only)
                + u32::from(*error_if_no_space);
            if set > 4 {
                return Err(Error::Usage(
                    "thin-pool accepts at most 4 feature flags; the kernel rejects all 5 at once".into(),
                ));
            }
        }
        Ok(())
    }

    /// Construct a [`Target::Verity`]. Data/hash block size is locked to
    /// 4096 and `hash_start_block` to 1 (see the variant docs); `digest`
    /// and `salt` are raw bytes, hex-encoded on write.
    pub fn verity(
        data_dev: DevId,
        hash_dev: DevId,
        num_data_blocks: u64,
        algorithm: impl Into<String>,
        digest: Vec<u8>,
        salt: Vec<u8>,
    ) -> Target {
        Target::Verity { data_dev, hash_dev, num_data_blocks, algorithm: algorithm.into(), digest, salt }
    }

    /// Start building a [`Target::ThinPool`]. Feature flags default to off;
    /// set the ones you need on the returned builder, then `.build()`.
    pub fn thin_pool(
        metadata: DevId,
        data: DevId,
        data_block_size_sectors: u64,
        low_water_mark_blocks: u64,
    ) -> ThinPoolBuilder {
        ThinPoolBuilder {
            metadata,
            data,
            data_block_size_sectors,
            low_water_mark_blocks,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: false,
            read_only: false,
            error_if_no_space: false,
        }
    }

    /// Start building a [`Target::Writecache`]. The watermark options
    /// default to unset (kernel defaults).
    pub fn writecache(kind: WritecacheKind, origin: DevId, cache: DevId, block_size: u32) -> WritecacheBuilder {
        WritecacheBuilder {
            kind,
            origin,
            cache,
            block_size,
            high_watermark_percent: None,
            low_watermark_percent: None,
        }
    }

    /// Start building a [`Target::Integrity`]. `tag_size`/`internal_hash`
    /// default to unset and `allow_discards` to false.
    pub fn integrity(device: DevId, reserved_sectors: u64, mode: IntegrityMode) -> IntegrityBuilder {
        IntegrityBuilder {
            device,
            reserved_sectors,
            mode,
            tag_size: None,
            internal_hash: None,
            allow_discards: false,
        }
    }
}

/// Builder for [`Target::ThinPool`] — see [`Target::thin_pool`]. At most
/// four feature flags may be set at once (the kernel rejects all five);
/// [`crate::Device::load_table`] enforces this.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // mirrors ThinPool's five kernel feature flags
pub struct ThinPoolBuilder {
    metadata: DevId,
    data: DevId,
    data_block_size_sectors: u64,
    low_water_mark_blocks: u64,
    skip_block_zeroing: bool,
    ignore_discard: bool,
    no_discard_passdown: bool,
    read_only: bool,
    error_if_no_space: bool,
}

impl ThinPoolBuilder {
    /// Don't zero newly-provisioned blocks before use.
    #[must_use]
    pub fn skip_block_zeroing(mut self, on: bool) -> Self {
        self.skip_block_zeroing = on;
        self
    }
    /// Disable discard support.
    #[must_use]
    pub fn ignore_discard(mut self, on: bool) -> Self {
        self.ignore_discard = on;
        self
    }
    /// Don't pass discards down to the underlying data device.
    #[must_use]
    pub fn no_discard_passdown(mut self, on: bool) -> Self {
        self.no_discard_passdown = on;
        self
    }
    /// Load the pool read-only.
    #[must_use]
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Error (rather than queue) I/O once the pool is out of space.
    #[must_use]
    pub fn error_if_no_space(mut self, on: bool) -> Self {
        self.error_if_no_space = on;
        self
    }
    /// Finish building the [`Target::ThinPool`].
    pub fn build(self) -> Target {
        Target::ThinPool {
            metadata: self.metadata,
            data: self.data,
            data_block_size_sectors: self.data_block_size_sectors,
            low_water_mark_blocks: self.low_water_mark_blocks,
            skip_block_zeroing: self.skip_block_zeroing,
            ignore_discard: self.ignore_discard,
            no_discard_passdown: self.no_discard_passdown,
            read_only: self.read_only,
            error_if_no_space: self.error_if_no_space,
        }
    }
}

/// Builder for [`Target::Writecache`] — see [`Target::writecache`].
#[derive(Debug, Clone)]
pub struct WritecacheBuilder {
    kind: WritecacheKind,
    origin: DevId,
    cache: DevId,
    block_size: u32,
    high_watermark_percent: Option<u32>,
    low_watermark_percent: Option<u32>,
}

impl WritecacheBuilder {
    /// Start writeback once the cache is this percent full.
    #[must_use]
    pub fn high_watermark_percent(mut self, percent: u32) -> Self {
        self.high_watermark_percent = Some(percent);
        self
    }
    /// Stop writeback once the cache drops to this percent full.
    #[must_use]
    pub fn low_watermark_percent(mut self, percent: u32) -> Self {
        self.low_watermark_percent = Some(percent);
        self
    }
    /// Finish building the [`Target::Writecache`].
    pub fn build(self) -> Target {
        Target::Writecache {
            kind: self.kind,
            origin: self.origin,
            cache: self.cache,
            block_size: self.block_size,
            high_watermark_percent: self.high_watermark_percent,
            low_watermark_percent: self.low_watermark_percent,
        }
    }
}

/// Builder for [`Target::Integrity`] — see [`Target::integrity`].
#[derive(Debug, Clone)]
pub struct IntegrityBuilder {
    device: DevId,
    reserved_sectors: u64,
    mode: IntegrityMode,
    tag_size: Option<u32>,
    internal_hash: Option<String>,
    allow_discards: bool,
}

impl IntegrityBuilder {
    /// Per-block integrity tag size in bytes.
    #[must_use]
    pub fn tag_size(mut self, bytes: u32) -> Self {
        self.tag_size = Some(bytes);
        self
    }
    /// Compute internal tags with this hash algorithm (e.g. `"sha256"`).
    #[must_use]
    pub fn internal_hash(mut self, algorithm: impl Into<String>) -> Self {
        self.internal_hash = Some(algorithm.into());
        self
    }
    /// Allow discards to pass through.
    #[must_use]
    pub fn allow_discards(mut self, on: bool) -> Self {
        self.allow_discards = on;
        self
    }
    /// Finish building the [`Target::Integrity`].
    pub fn build(self) -> Target {
        Target::Integrity {
            device: self.device,
            reserved_sectors: self.reserved_sectors,
            tag_size: self.tag_size,
            mode: self.mode,
            internal_hash: self.internal_hash,
            allow_discards: self.allow_discards,
        }
    }
}

/// Raw *argument-token* count a [`FlakeyFeature`] contributes to the
/// table line's `<#num_features>` field — the kernel counts shifted
/// tokens, not feature groups: a bare flag is 1 token, `corrupt_bio_byte`
/// is 5 (itself plus 4 args), the `random_*_corrupt` features are 2
/// (themselves plus 1 arg each). Verified against `dm-flakey.c`'s status
/// callback, which emits exactly these weights.
fn flakey_feature_token_count(feature: &FlakeyFeature) -> u32 {
    match feature {
        FlakeyFeature::ErrorReads | FlakeyFeature::DropWrites | FlakeyFeature::ErrorWrites => 1,
        FlakeyFeature::CorruptBioByte { .. } => 5,
        FlakeyFeature::RandomReadCorrupt { .. } | FlakeyFeature::RandomWriteCorrupt { .. } => 2,
    }
}

fn write_flakey_feature(w: &mut dyn fmt::Write, feature: &FlakeyFeature) -> fmt::Result {
    match feature {
        FlakeyFeature::ErrorReads => w.write_str(" error_reads"),
        FlakeyFeature::DropWrites => w.write_str(" drop_writes"),
        FlakeyFeature::ErrorWrites => w.write_str(" error_writes"),
        FlakeyFeature::CorruptBioByte { nth_byte, direction, value, flags } => {
            let direction = match direction {
                FlakeyDirection::Read => 'r',
                FlakeyDirection::Write => 'w',
            };
            write!(w, " corrupt_bio_byte {nth_byte} {direction} {value} {flags}")
        }
        FlakeyFeature::RandomReadCorrupt { probability } => write!(w, " random_read_corrupt {probability}"),
        FlakeyFeature::RandomWriteCorrupt { probability } => write!(w, " random_write_corrupt {probability}"),
    }
}

fn parse_device(s: &str) -> Option<DevId> {
    let (maj, min) = s.split_once(':')?;
    Some(DevId::new(maj.parse().ok()?, min.parse().ok()?))
}

fn parse_linear(params: &str) -> Option<Target> {
    let mut it = params.split_whitespace();
    let device = parse_device(it.next()?)?;
    let offset_sectors = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some(Target::Linear { device, offset_sectors })
}

fn parse_snapshot_origin(params: &str) -> Option<Target> {
    let mut it = params.split_whitespace();
    let origin = parse_device(it.next()?)?;
    if it.next().is_some() {
        return None;
    }
    Some(Target::SnapshotOrigin { origin })
}

/// One `<start> <length> <target>` row of a dm table. Renders to its
/// operator-facing kernel-ABI form via [`fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TableLine {
    pub start: u64,
    pub length: u64,
    pub target: Target,
}

impl TableLine {
    /// A table row mapping sectors `[start, start + length)` to `target`.
    pub fn new(start: u64, length: u64, target: Target) -> Self {
        Self { start, length, target }
    }
}

impl fmt::Display for TableLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.start, self.length, self.target)
    }
}

impl fmt::Display for Target {
    /// The `<type> <params>` portion of a table line (no leading
    /// start/length). A target with no parameters (e.g. `zero`) renders as
    /// just its type name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.name()))?;
        let mut params = String::new();
        self.params(&mut params)?;
        if !params.is_empty() {
            write!(f, " {params}")?;
        }
        Ok(())
    }
}

/// `fmt::Write` adapter that counts written bytes without buffering.
struct CountingWriter(usize);
impl fmt::Write for CountingWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// `fmt::Write` adapter that writes into a fixed slot of `&mut [u8]`.
struct SliceWriter<'a> {
    bytes: &'a mut [u8],
    pos: usize,
}
impl fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.pos + s.len();
        self.bytes[self.pos..end].copy_from_slice(s.as_bytes());
        self.pos = end;
        Ok(())
    }
}

/// Operator-facing `<start> <length> <type> <params>` rendering, for
/// attaching to a failed `DM_TABLE_LOAD`'s error. Thin wrapper over
/// [`TableLine`]'s [`fmt::Display`].
pub(crate) fn render_line(line: &TableLine) -> String {
    line.to_string()
}

pub(crate) fn render_all(lines: &[TableLine]) -> String {
    lines.iter().map(render_line).collect::<Vec<_>>().join("\n")
}

/// Owned `Vec<u8>` containing a `DmHeader` followed by per-target
/// `dm_target_spec_raw` + parameter strings, for `DM_TABLE_LOAD`.
pub(crate) struct DmTableBuf {
    bytes: Vec<u8>,
}

impl DmTableBuf {
    // Table byte-buffer sizes and line counts never approach u32::MAX in
    // practice; the kernel's own dm_ioctl/dm_target_spec fields are u32.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn build(dev_t: DevId, lines: &[TableLine]) -> Result<Self, Error> {
        let header_size = DmHeader::SIZE;

        let mut aligned_lens = Vec::with_capacity(lines.len());
        let mut payload_len = 0usize;
        for line in lines {
            if line.target.name().len() >= DM_MAX_TYPE_NAME {
                return Err(Error::Usage(format!(
                    "target type name too long: {:?}",
                    String::from_utf8_lossy(line.target.name())
                )));
            }
            line.target.validate()?;
            let mut counter = CountingWriter(0);
            line.target.params(&mut counter).expect("CountingWriter is infallible");
            let aligned = (DM_TARGET_SPEC_SIZE + counter.0 + 1).next_multiple_of(8);
            aligned_lens.push(aligned);
            payload_len += aligned;
        }
        let total_len = header_size + payload_len;

        let mut bytes = vec![0u8; total_len];

        let mut header = DmHeader::by_dev(dev_t.to_dev_t());
        header.set_data_size(total_len as u32);
        header.set_target_count(lines.len() as u32);
        bytes[..header_size].copy_from_slice(header.as_bytes());

        let mut abs_offset = header_size;
        let last_idx = lines.len().saturating_sub(1);
        for (i, line) in lines.iter().enumerate() {
            let aligned_len = aligned_lens[i];
            let next_offset = if i == last_idx { 0 } else { aligned_len as u32 };

            let mut target_type = [0u8; DM_MAX_TYPE_NAME];
            let tn = line.target.name();
            target_type[..tn.len()].copy_from_slice(tn);

            let spec = dm_target_spec_raw {
                sector_start: line.start,
                length: line.length,
                status: 0,
                next: next_offset,
                target_type,
            };
            bytes[abs_offset..abs_offset + DM_TARGET_SPEC_SIZE].copy_from_slice(spec.as_bytes());

            let param_offset = abs_offset + DM_TARGET_SPEC_SIZE;
            let param_slot_end = abs_offset + aligned_len - 1; // -1 reserves the NUL byte
            let mut writer = SliceWriter { bytes: &mut bytes[param_offset..param_slot_end], pos: 0 };
            line.target
                .params(&mut writer)
                .expect("SliceWriter is infallible: slot was sized in the measure pass");

            abs_offset += aligned_len;
        }

        Ok(Self { bytes })
    }

    pub(crate) fn header_mut(&mut self) -> &mut DmHeader {
        let (h, _) = zerocopy::FromBytes::mut_from_prefix(&mut self.bytes)
            .expect("DmTableBuf invariant: bytes[..DmHeader::SIZE] is a valid DmHeader");
        h
    }
}

/// Parses `DM_TABLE_STATUS`'s response into [`TableLine`]s. Not exported
/// — `Device::table_status()` returns `impl Iterator<Item = TableLine>`.
///
/// `dm_target_spec.next` means something different here than on the
/// write side: for `DM_TABLE_STATUS` it's the byte offset from the
/// *first* spec's start to the next one, not from the current spec's
/// start (see `<linux/dm-ioctl.h>`'s comment on `struct dm_target_spec`).
pub(crate) struct TableStatusIter {
    buf: Vec<u8>,
    first: usize,
    offset: usize,
    remaining: u32,
}

impl TableStatusIter {
    pub(crate) fn new(buf: Vec<u8>, target_count: u32) -> Self {
        let first = DmHeader::SIZE;
        Self { buf, first, offset: first, remaining: target_count }
    }
}

impl Iterator for TableStatusIter {
    type Item = TableLine;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.offset + DM_TARGET_SPEC_SIZE > self.buf.len() {
            return None;
        }

        let spec = &self.buf[self.offset..self.offset + DM_TARGET_SPEC_SIZE];
        let sector_start = u64::from_ne_bytes(spec[0..8].try_into().unwrap());
        let length = u64::from_ne_bytes(spec[8..16].try_into().unwrap());
        let next = u32::from_ne_bytes(spec[20..24].try_into().unwrap());
        let type_field = &spec[24..24 + DM_MAX_TYPE_NAME];
        let type_nul = type_field.iter().position(|&b| b == 0).unwrap_or(type_field.len());
        let kernel_type_name = &type_field[..type_nul];

        let param_start = self.offset + DM_TARGET_SPEC_SIZE;
        let param_area = &self.buf[param_start..];
        let param_nul = param_area.iter().position(|&b| b == 0).unwrap_or(param_area.len());
        let params = String::from_utf8_lossy(&param_area[..param_nul]);

        let target = Target::from_status(kernel_type_name, &params);

        self.remaining -= 1;
        self.offset = if next == 0 { self.buf.len() } else { self.first + next as usize };

        Some(TableLine { start: sector_start, length, target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_kernel_abi_is_empty() {
        let t = TableLine { start: 0, length: 8, target: Target::Zero };
        assert_eq!(render_line(&t), "0 8 zero");
    }

    #[test]
    fn linear_renders_device_and_offset() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::Linear { device: DevId::new(252, 5), offset_sectors: 5 },
        };
        assert_eq!(render_line(&t), "0 1024 linear 252:5 5");
    }

    #[test]
    fn snapshot_renders_with_po_persistence() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::Snapshot { origin: DevId::new(252, 1), cow: DevId::new(252, 2), chunk_size_sectors: 8 },
        };
        assert_eq!(render_line(&t), "0 1024 snapshot 252:1 252:2 PO 8");
    }

    #[test]
    fn verity_renders_per_kernel_docs() {
        let t = TableLine {
            start: 0,
            length: 80,
            target: Target::Verity {
                data_dev: DevId::new(252, 100),
                hash_dev: DevId::new(252, 101),
                num_data_blocks: 10,
                algorithm: "sha256".into(),
                digest: vec![0xBB; 32],
                salt: vec![0xAA; 32],
            },
        };
        let line = render_line(&t);
        assert!(line.contains("verity 1 252:100 252:101 4096 4096 10 1 sha256"));
        let toks: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(*toks.last().unwrap(), "aa".repeat(32));
        assert_eq!(toks[toks.len() - 2], "bb".repeat(32));
    }

    #[test]
    fn striped_renders_stripe_count_and_pairs() {
        let t = TableLine {
            start: 0,
            length: 2048,
            target: Target::Striped {
                chunk_size_sectors: 128,
                stripes: vec![(DevId::new(252, 1), 0), (DevId::new(252, 2), 0)],
            },
        };
        assert_eq!(render_line(&t), "0 2048 striped 2 128 252:1 0 252:2 0");
    }

    #[test]
    fn buf_for_zero_target_has_correct_layout() {
        let lines = [TableLine { start: 0, length: 8, target: Target::Zero }];
        let mut buf = DmTableBuf::build(DevId::new(252, 5), &lines).unwrap();
        // 312 header + (40 spec + 0 params + 1 NUL = 41 -> padded to 48).
        assert_eq!(buf.bytes.len(), 312 + 48);
        assert_eq!(buf.header_mut().major_version(), 4);
    }

    #[test]
    fn from_status_round_trips_trivial_targets() {
        assert_eq!(Target::from_status(b"zero", ""), Target::Zero);
        assert_eq!(Target::from_status(b"error", ""), Target::ErrorTarget);
        assert_eq!(
            Target::from_status(b"linear", "252:5 5"),
            Target::Linear { device: DevId::new(252, 5), offset_sectors: 5 }
        );
        assert_eq!(
            Target::from_status(b"snapshot-origin", "252:1"),
            Target::SnapshotOrigin { origin: DevId::new(252, 1) }
        );
    }

    #[test]
    fn from_status_falls_back_to_other_for_non_roundtrippable_targets() {
        // A verity status string ("V") looks nothing like its creation
        // params, so it must not be misinterpreted as one.
        match Target::from_status(b"verity", "V") {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"verity");
                assert_eq!(params, "V");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn from_status_falls_back_to_other_for_unrecognized_types() {
        match Target::from_status(b"thin-pool", "some future format") {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"thin-pool");
                assert_eq!(params, "some future format");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // --- gaps closed below: ErrorTarget/SnapshotOrigin write-side, ---
    // --- Snapshot/Striped from_status fallback, Other write-side ---

    #[test]
    fn error_target_kernel_abi_is_empty() {
        let t = TableLine { start: 0, length: 8, target: Target::ErrorTarget };
        assert_eq!(render_line(&t), "0 8 error");
    }

    #[test]
    fn snapshot_origin_renders_device_only() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::SnapshotOrigin { origin: DevId::new(252, 1) },
        };
        assert_eq!(render_line(&t), "0 1024 snapshot-origin 252:1");
    }

    #[test]
    fn from_status_falls_back_to_other_for_snapshot_and_striped() {
        // Both share Verity's fallback code path (the `_` arm), but that's
        // an implementation-sharing argument, not a test — assert each
        // explicitly rather than trusting they behave like Verity because
        // they happen to run through the same match arm today.
        match Target::from_status(b"snapshot", "512/1024 1") {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"snapshot");
                assert_eq!(params, "512/1024 1");
            }
            other => panic!("expected Other, got {other:?}"),
        }
        match Target::from_status(b"striped", "2 128 252:1 0 252:2 0") {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"striped");
                assert_eq!(params, "2 128 252:1 0 252:2 0");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn other_renders_its_stored_params_verbatim() {
        let t = TableLine {
            start: 0,
            length: 8,
            target: Target::Other {
                kernel_type_name: b"my-custom-target".to_vec(),
                params: "1 2 3".into(),
            },
        };
        assert_eq!(render_line(&t), "0 8 my-custom-target 1 2 3");
    }

    #[test]
    fn buf_for_linear_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 1024,
            target: Target::Linear { device: DevId::new(252, 5), offset_sectors: 0 },
        }];
        let mut buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let params = "252:5 0";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(buf.bytes.len(), DmHeader::SIZE + aligned);
        assert_eq!(buf.header_mut().major_version(), 4);

        let bytes = &buf.bytes;
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
        assert_eq!(bytes[param_start + params.len()], 0); // NUL terminator
        let type_field = &bytes[DmHeader::SIZE + 24..DmHeader::SIZE + 24 + 16];
        assert_eq!(&type_field[..6], b"linear");
    }

    #[test]
    fn buf_for_verity_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 56,
            target: Target::Verity {
                data_dev: DevId::new(253, 3),
                hash_dev: DevId::new(253, 4),
                num_data_blocks: 7,
                algorithm: "sha256".into(),
                digest: vec![0xCD; 32],
                salt: vec![0x55; 32],
            },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let cd_hex = "cd".repeat(32);
        let salt_hex = "55".repeat(32);
        let params = format!("1 253:3 253:4 4096 4096 7 1 sha256 {cd_hex} {salt_hex}");
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(buf.bytes.len(), DmHeader::SIZE + aligned);

        let bytes = &buf.bytes;
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
        assert_eq!(bytes[param_start + params.len()], 0);
    }

    #[test]
    fn buf_for_snapshot_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 1024,
            target: Target::Snapshot { origin: DevId::new(252, 1), cow: DevId::new(252, 2), chunk_size_sectors: 8 },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let params = "252:1 252:2 PO 8";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(buf.bytes.len(), DmHeader::SIZE + aligned);

        let bytes = &buf.bytes;
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
        assert_eq!(bytes[param_start + params.len()], 0);
    }

    #[test]
    fn buf_for_striped_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 2048,
            target: Target::Striped {
                chunk_size_sectors: 128,
                stripes: vec![(DevId::new(252, 1), 0), (DevId::new(252, 2), 0)],
            },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let params = "2 128 252:1 0 252:2 0";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(buf.bytes.len(), DmHeader::SIZE + aligned);

        let bytes = &buf.bytes;
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
        assert_eq!(bytes[param_start + params.len()], 0);
    }

    #[test]
    fn buf_for_three_target_table_chains_specs_with_offsets_relative_to_current() {
        // Write-side `next` is relative to *each spec's own* start (unlike
        // the read side — see TableStatusIter's test below for the
        // opposite convention). Three lines, not two: with only two, the
        // first spec's `next` can't distinguish "relative to current" from
        // "relative to first" (they're the same for entry 0 either way).
        let lines = [
            TableLine { start: 0, length: 8, target: Target::Zero },
            TableLine {
                start: 8,
                length: 1024,
                target: Target::Linear { device: DevId::new(252, 5), offset_sectors: 5 },
            },
            TableLine { start: 1032, length: 8, target: Target::ErrorTarget },
        ];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let bytes = &buf.bytes;

        let zero_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        let linear_aligned = (DM_TARGET_SPEC_SIZE + "252:5 5".len() + 1).next_multiple_of(8);
        let error_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        assert_eq!(bytes.len(), DmHeader::SIZE + zero_aligned + linear_aligned + error_aligned);

        let spec0 = DmHeader::SIZE;
        let spec1 = spec0 + zero_aligned;
        let spec2 = spec1 + linear_aligned;

        let next0 = u32::from_ne_bytes(bytes[spec0 + 20..spec0 + 24].try_into().unwrap());
        let next1 = u32::from_ne_bytes(bytes[spec1 + 20..spec1 + 24].try_into().unwrap());
        let next2 = u32::from_ne_bytes(bytes[spec2 + 20..spec2 + 24].try_into().unwrap());

        #[allow(clippy::cast_possible_truncation)]
        {
            assert_eq!(next0, zero_aligned as u32, "spec0.next: bytes from spec0's own start to spec1");
            assert_eq!(next1, linear_aligned as u32, "spec1.next: bytes from spec1's own start to spec2");
        }
        assert_eq!(next2, 0, "last spec's next must be 0");
    }

    /// Hand-builds a synthetic `DM_TABLE_STATUS`-shaped response buffer:
    /// header + N `dm_target_spec` entries whose `next` fields use the
    /// *read*-direction convention (offset from the *first* spec's start,
    /// not the current one — see `<linux/dm-ioctl.h>`'s comment on
    /// `struct dm_target_spec`), each followed by a NUL-terminated status
    /// string. Deliberately independent of `DmTableBuf` (the write-side
    /// builder), since this is testing the reader against what a real
    /// kernel response looks like, not testing our own writer against
    /// itself.
    // Test-only helper building tiny fixture buffers; lengths never approach u32::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn synthetic_table_status_response(entries: &[(&[u8], &str)]) -> (Vec<u8>, u32) {
        let first = DmHeader::SIZE;
        let mut aligned_lens = Vec::with_capacity(entries.len());
        let mut payload_len = 0usize;
        for (_, params) in entries {
            let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
            aligned_lens.push(aligned);
            payload_len += aligned;
        }
        let mut bytes = vec![0u8; first + payload_len];

        let mut abs_offset_from_first = 0usize;
        for (i, (type_name, params)) in entries.iter().enumerate() {
            let abs_offset = first + abs_offset_from_first;
            let aligned_len = aligned_lens[i];
            let next = if i == entries.len() - 1 {
                0
            } else {
                (abs_offset_from_first + aligned_len) as u32
            };

            bytes[abs_offset..abs_offset + 8].copy_from_slice(&0u64.to_ne_bytes()); // sector_start
            bytes[abs_offset + 8..abs_offset + 16].copy_from_slice(&0u64.to_ne_bytes()); // length
            bytes[abs_offset + 20..abs_offset + 24].copy_from_slice(&next.to_ne_bytes());
            let type_field = &mut bytes[abs_offset + 24..abs_offset + 24 + DM_MAX_TYPE_NAME];
            type_field[..type_name.len()].copy_from_slice(type_name);

            let param_start = abs_offset + DM_TARGET_SPEC_SIZE;
            bytes[param_start..param_start + params.len()].copy_from_slice(params.as_bytes());

            abs_offset_from_first += aligned_len;
        }

        (bytes, entries.len() as u32)
    }

    #[test]
    fn table_status_iter_parses_single_entry() {
        let (bytes, count) = synthetic_table_status_response(&[(b"zero", "")]);
        let lines: Vec<TableLine> = TableStatusIter::new(bytes, count).collect();
        assert_eq!(lines, [TableLine { start: 0, length: 0, target: Target::Zero }]);
    }

    #[test]
    fn table_status_iter_follows_next_relative_to_first_spec() {
        // Three entries with different-length status strings, so a parser
        // that incorrectly treated `next` as relative to the *current*
        // spec (the write-side convention) would land on garbage instead
        // of the real next entry.
        let (bytes, count) = synthetic_table_status_response(&[
            (b"zero", ""),
            (b"linear", "252:5 5"),
            (b"error", ""),
        ]);
        let lines: Vec<TableLine> = TableStatusIter::new(bytes, count).collect();
        assert_eq!(
            lines,
            [
                TableLine { start: 0, length: 0, target: Target::Zero },
                TableLine {
                    start: 0,
                    length: 0,
                    target: Target::Linear { device: DevId::new(252, 5), offset_sectors: 5 }
                },
                TableLine { start: 0, length: 0, target: Target::ErrorTarget },
            ]
        );
    }

    #[test]
    fn from_status_linear_falls_back_to_other_on_malformed_params() {
        // Every parse_linear rejection path must degrade to Other with the
        // original name/params preserved verbatim, never panic or misparse.
        for params in ["252:5 5 6" /* trailing */, "garbage" /* no colon */, "252:x 5" /* bad minor */, ""] {
            match Target::from_status(b"linear", params) {
                Target::Other { kernel_type_name, params: got } => {
                    assert_eq!(kernel_type_name, b"linear");
                    assert_eq!(got, params);
                }
                other => panic!("expected Other for linear {params:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn from_status_snapshot_origin_falls_back_to_other_on_trailing_tokens() {
        match Target::from_status(b"snapshot-origin", "252:1 extra") {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"snapshot-origin");
                assert_eq!(params, "252:1 extra");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn table_status_iter_stops_when_count_exceeds_available_specs() {
        // target_count claims 3 but the buffer holds only 1 spec: the
        // bounds guard must terminate cleanly instead of reading past the end.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let lines: Vec<TableLine> = TableStatusIter::new(bytes, 3).collect();
        assert_eq!(lines, [TableLine { start: 0, length: 0, target: Target::Zero }]);
    }

    #[test]
    fn table_status_iter_next_zero_terminates_before_remaining_reaches_zero() {
        // A single real entry whose next==0, but remaining=2: the next==0
        // jump-to-end must win over the remaining counter.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let lines: Vec<TableLine> = TableStatusIter::new(bytes, 2).collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn table_status_iter_reports_unrecognized_targets_as_other() {
        let (bytes, count) = synthetic_table_status_response(&[(b"thin-pool", "some status")]);
        let lines: Vec<TableLine> = TableStatusIter::new(bytes, count).collect();
        match &lines[0].target {
            Target::Other { kernel_type_name, params } => {
                assert_eq!(kernel_type_name, b"thin-pool");
                assert_eq!(params, "some status");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    // --- New target rendering (trivial + low tier) -------------------

    #[test]
    fn delay_renders_three_arg_form_when_only_read_is_set() {
        let t = TableLine {
            start: 0,
            length: 8,
            target: Target::Delay {
                read: DelayLeg { device: DevId::new(252, 1), offset_sectors: 0, delay_ms: 500 },
                write: None,
                flush: None,
            },
        };
        assert_eq!(render_line(&t), "0 8 delay 252:1 0 500");
    }

    #[test]
    fn delay_renders_six_arg_form_when_write_is_set() {
        let t = TableLine {
            start: 0,
            length: 8,
            target: Target::Delay {
                read: DelayLeg { device: DevId::new(252, 1), offset_sectors: 0, delay_ms: 500 },
                write: Some(DelayLeg { device: DevId::new(252, 2), offset_sectors: 0, delay_ms: 100 }),
                flush: None,
            },
        };
        assert_eq!(render_line(&t), "0 8 delay 252:1 0 500 252:2 0 100");
    }

    #[test]
    fn delay_renders_nine_arg_form_when_flush_is_set() {
        let t = TableLine {
            start: 0,
            length: 8,
            target: Target::Delay {
                read: DelayLeg { device: DevId::new(252, 1), offset_sectors: 0, delay_ms: 500 },
                write: Some(DelayLeg { device: DevId::new(252, 2), offset_sectors: 0, delay_ms: 100 }),
                flush: Some(DelayLeg { device: DevId::new(252, 3), offset_sectors: 0, delay_ms: 50 }),
            },
        };
        assert_eq!(render_line(&t), "0 8 delay 252:1 0 500 252:2 0 100 252:3 0 50");
    }

    #[test]
    fn delay_flush_without_explicit_write_falls_back_to_read_leg() {
        let t = TableLine {
            start: 0,
            length: 8,
            target: Target::Delay {
                read: DelayLeg { device: DevId::new(252, 1), offset_sectors: 0, delay_ms: 500 },
                write: None,
                flush: Some(DelayLeg { device: DevId::new(252, 3), offset_sectors: 0, delay_ms: 50 }),
            },
        };
        assert_eq!(render_line(&t), "0 8 delay 252:1 0 500 252:1 0 500 252:3 0 50");
    }

    #[test]
    fn unstriped_renders_all_fields() {
        let t = TableLine {
            start: 0,
            length: 512,
            target: Target::Unstriped {
                stripes: 2,
                chunk_size_sectors: 256,
                stripe_index: 0,
                device: DevId::new(252, 1),
                offset_sectors: 0,
            },
        };
        assert_eq!(render_line(&t), "0 512 unstriped 2 256 0 252:1 0");
    }

    #[test]
    fn dust_renders_device_offset_and_block_size() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Dust { device: DevId::new(252, 1), offset_sectors: 0, block_size: 512 },
        };
        assert_eq!(render_line(&t), "0 8192 dust 252:1 0 512");
    }

    #[test]
    fn era_renders_metadata_origin_and_block_size() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Era { metadata: DevId::new(252, 1), origin: DevId::new(252, 2), block_size: 128 },
        };
        assert_eq!(render_line(&t), "0 8192 era 252:1 252:2 128");
    }

    #[test]
    fn log_writes_renders_both_devices() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::LogWrites { device: DevId::new(252, 1), log_device: DevId::new(252, 2) },
        };
        assert_eq!(render_line(&t), "0 8192 log-writes 252:1 252:2");
    }

    #[test]
    fn snapshot_merge_renders_like_snapshot_with_po() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::SnapshotMerge { origin: DevId::new(252, 1), cow: DevId::new(252, 2), chunk_size_sectors: 8 },
        };
        assert_eq!(render_line(&t), "0 1024 snapshot-merge 252:1 252:2 PO 8");
    }

    #[test]
    fn zoned_renders_device_only() {
        let t = TableLine { start: 0, length: 8192, target: Target::Zoned { device: DevId::new(252, 1) } };
        assert_eq!(render_line(&t), "0 8192 zoned 252:1");
    }

    #[test]
    fn flakey_renders_zero_features_when_none_given() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Flakey {
                device: DevId::new(252, 1),
                offset_sectors: 0,
                up_interval_secs: 60,
                down_interval_secs: 5,
                features: vec![],
            },
        };
        assert_eq!(render_line(&t), "0 8192 flakey 252:1 0 60 5 0");
    }

    #[test]
    fn flakey_renders_feature_token_counts_not_feature_counts() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Flakey {
                device: DevId::new(252, 1),
                offset_sectors: 0,
                up_interval_secs: 60,
                down_interval_secs: 5,
                features: vec![
                    FlakeyFeature::ErrorReads,
                    FlakeyFeature::CorruptBioByte {
                        nth_byte: 32,
                        direction: FlakeyDirection::Write,
                        value: 1,
                        flags: 0,
                    },
                    FlakeyFeature::RandomWriteCorrupt { probability: 10 },
                ],
            },
        };
        // token count: error_reads(1) + corrupt_bio_byte(5) + random_write_corrupt(2) = 8
        assert_eq!(
            render_line(&t),
            "0 8192 flakey 252:1 0 60 5 8 error_reads corrupt_bio_byte 32 w 1 0 random_write_corrupt 10"
        );
    }

    #[test]
    fn writecache_renders_mode_and_optional_watermarks() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Writecache {
                kind: WritecacheKind::Ssd,
                origin: DevId::new(252, 1),
                cache: DevId::new(252, 2),
                block_size: 4096,
                high_watermark_percent: Some(90),
                low_watermark_percent: None,
            },
        };
        assert_eq!(render_line(&t), "0 8192 writecache s 252:1 252:2 4096 2 high_watermark 90");
    }

    #[test]
    fn writecache_renders_pmem_with_no_optional_args() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Writecache {
                kind: WritecacheKind::PersistentMemory,
                origin: DevId::new(252, 1),
                cache: DevId::new(252, 2),
                block_size: 4096,
                high_watermark_percent: None,
                low_watermark_percent: None,
            },
        };
        assert_eq!(render_line(&t), "0 8192 writecache p 252:1 252:2 4096 0");
    }

    #[test]
    fn integrity_renders_dash_for_unset_tag_size() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Integrity {
                device: DevId::new(252, 1),
                reserved_sectors: 0,
                tag_size: None,
                mode: IntegrityMode::Journaled,
                internal_hash: None,
                allow_discards: false,
            },
        };
        assert_eq!(render_line(&t), "0 8192 integrity 252:1 0 - J 0");
    }

    #[test]
    fn integrity_renders_optional_args() {
        let t = TableLine {
            start: 0,
            length: 8192,
            target: Target::Integrity {
                device: DevId::new(252, 1),
                reserved_sectors: 0,
                tag_size: Some(32),
                mode: IntegrityMode::Direct,
                internal_hash: Some("sha256".into()),
                allow_discards: true,
            },
        };
        assert_eq!(render_line(&t), "0 8192 integrity 252:1 0 32 D 2 internal_hash:sha256 allow_discards");
    }

    #[test]
    fn raid_renders_type_chunk_size_and_device_pairs() {
        let t = TableLine {
            start: 0,
            length: 1_048_576,
            target: Target::Raid {
                raid_type: RaidType::Raid1,
                chunk_size_sectors: 128,
                devices: vec![RaidDevicePair::new(None, DevId::new(252, 1)), RaidDevicePair::new(Some(DevId::new(252, 2)), DevId::new(252, 3))],
            },
        };
        assert_eq!(render_line(&t), "0 1048576 raid raid1 1 128 2 - 252:1 252:2 252:3");
    }

    #[test]
    fn thin_pool_renders_only_set_feature_flags() {
        let t = TableLine {
            start: 0,
            length: 1_048_576,
            target: Target::ThinPool {
                metadata: DevId::new(252, 1),
                data: DevId::new(252, 2),
                data_block_size_sectors: 128,
                low_water_mark_blocks: 0,
                skip_block_zeroing: false,
                ignore_discard: false,
                no_discard_passdown: true,
                read_only: false,
                error_if_no_space: true,
            },
        };
        assert_eq!(
            render_line(&t),
            "0 1048576 thin-pool 252:1 252:2 128 0 2 no_discard_passdown error_if_no_space"
        );
    }

    #[test]
    fn thin_renders_without_external_origin() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::Thin { pool: DevId::new(252, 1), dev_id: 7, external_origin: None },
        };
        assert_eq!(render_line(&t), "0 1024 thin 252:1 7");
    }

    #[test]
    fn thin_renders_with_external_origin() {
        let t = TableLine {
            start: 0,
            length: 1024,
            target: Target::Thin { pool: DevId::new(252, 1), dev_id: 7, external_origin: Some(DevId::new(252, 9)) },
        };
        assert_eq!(render_line(&t), "0 1024 thin 252:1 7 252:9");
    }

    // --- New targets' status never matches their ctor shape -----------
    //
    // Verified against every new target's kernel source: DM_TABLE_STATUS
    // (STATUSTYPE_INFO) always reports live runtime data (op counts,
    // allocation stats, bad-block mode, ...), never an echo of the
    // creation parameters — that echo only happens under
    // STATUSTYPE_TABLE, which this crate's `table_status()` doesn't
    // request. So every new kernel_type_name here already falls through
    // `from_status`'s wildcard arm to `Other`, same as `Striped`/
    // `Verity`/`Snapshot`.
    #[test]
    fn from_status_falls_back_to_other_for_every_new_target() {
        let cases: &[(&[u8], &str)] = &[
            (b"delay", "0 0 0"),
            (b"unstriped", ""),
            (b"dust", "252:1 bypass verbose"),
            (b"era", "8 0/16384 3 -"),
            (b"log-writes", "12 4096"),
            (b"snapshot-merge", "281688/2097152 1104"),
            (b"zoned", "128 zones 4/8 cache"),
            (b"flakey", ""),
            (b"writecache", "0 100 0 0 0 0 0 0 0 0 0 0 0"),
            (b"integrity", "0 1000000 -"),
            (b"raid", "raid1 2 AA 1.000000 idle 0"),
            (b"thin-pool", "0 1/16384 0/1024 - rw discard_passdown - -"),
            (b"thin", "1024 2048"),
        ];
        for (kernel_type_name, params) in cases {
            match Target::from_status(kernel_type_name, params) {
                Target::Other { kernel_type_name: got_name, params: got_params } => {
                    assert_eq!(got_name, *kernel_type_name);
                    assert_eq!(got_params, *params);
                }
                other => panic!("expected Other for {kernel_type_name:?}, got {other:?}"),
            }
        }
    }

    // --- DmTableBuf byte-layout spot checks for the new variable-arity
    //     targets (Flakey's feature list, Raid's device-pair list,
    //     ThinPool's feature-flag list) — the fixed-arity targets above
    //     are already covered by their render tests, since DmTableBuf
    //     writes exactly the string `params()` produces.

    #[test]
    fn buf_for_flakey_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 8192,
            target: Target::Flakey {
                device: DevId::new(252, 1),
                offset_sectors: 0,
                up_interval_secs: 60,
                down_interval_secs: 5,
                features: vec![FlakeyFeature::ErrorReads],
            },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let bytes = &buf.bytes;

        let params = "252:1 0 60 5 1 error_reads";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(bytes.len(), DmHeader::SIZE + aligned);

        let spec = DmHeader::SIZE;
        let type_field = &bytes[spec + 24..spec + 24 + DM_MAX_TYPE_NAME];
        let nul = type_field.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&type_field[..nul], b"flakey");

        let param_start = spec + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
    }

    #[test]
    fn buf_for_raid_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 1_048_576,
            target: Target::Raid {
                raid_type: RaidType::Raid1,
                chunk_size_sectors: 128,
                devices: vec![RaidDevicePair::new(None, DevId::new(252, 1)), RaidDevicePair::new(None, DevId::new(252, 2))],
            },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let bytes = &buf.bytes;

        let params = "raid1 1 128 2 - 252:1 - 252:2";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(bytes.len(), DmHeader::SIZE + aligned);

        let spec = DmHeader::SIZE;
        let type_field = &bytes[spec + 24..spec + 24 + DM_MAX_TYPE_NAME];
        let nul = type_field.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&type_field[..nul], b"raid");

        let param_start = spec + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
    }

    #[test]
    fn buf_for_thin_pool_target_has_correct_layout_and_params() {
        let lines = [TableLine {
            start: 0,
            length: 1_048_576,
            target: Target::ThinPool {
                metadata: DevId::new(252, 1),
                data: DevId::new(252, 2),
                data_block_size_sectors: 128,
                low_water_mark_blocks: 0,
                skip_block_zeroing: true,
                ignore_discard: false,
                no_discard_passdown: false,
                read_only: false,
                error_if_no_space: false,
            },
        }];
        let buf = DmTableBuf::build(DevId::new(252, 9), &lines).unwrap();
        let bytes = &buf.bytes;

        let params = "252:1 252:2 128 0 1 skip_block_zeroing";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(bytes.len(), DmHeader::SIZE + aligned);

        let spec = DmHeader::SIZE;
        let type_field = &bytes[spec + 24..spec + 24 + DM_MAX_TYPE_NAME];
        let nul = type_field.iter().position(|&b| b == 0).unwrap();
        assert_eq!(&type_field[..nul], b"thin-pool");

        let param_start = spec + DM_TARGET_SPEC_SIZE;
        assert_eq!(&bytes[param_start..param_start + params.len()], params.as_bytes());
    }

    #[allow(clippy::fn_params_excessive_bools)] // mirrors ThinPool's five feature-flag fields 1:1
    fn thin_pool_with_flags(
        skip_block_zeroing: bool,
        ignore_discard: bool,
        no_discard_passdown: bool,
        read_only: bool,
        error_if_no_space: bool,
    ) -> Target {
        Target::ThinPool {
            metadata: DevId::new(252, 1),
            data: DevId::new(252, 2),
            data_block_size_sectors: 128,
            low_water_mark_blocks: 0,
            skip_block_zeroing,
            ignore_discard,
            no_discard_passdown,
            read_only,
            error_if_no_space,
        }
    }

    #[test]
    fn thin_pool_with_all_five_feature_flags_is_rejected_at_build() {
        // The kernel's parse_pool_features caps the feature count at 4 and
        // rejects 5 with EINVAL before inspecting keywords, so building the
        // table must fail early with Error::Usage rather than rendering a
        // line the kernel refuses.
        let lines = [TableLine { start: 0, length: 1024, target: thin_pool_with_flags(true, true, true, true, true) }];
        assert!(matches!(DmTableBuf::build(DevId::new(252, 9), &lines), Err(Error::Usage(_))));
    }

    #[test]
    fn thin_pool_with_four_feature_flags_builds() {
        // Four flags is the kernel's maximum and must still build.
        let lines = [TableLine { start: 0, length: 1024, target: thin_pool_with_flags(true, true, true, true, false) }];
        assert!(DmTableBuf::build(DevId::new(252, 9), &lines).is_ok());
    }

    #[test]
    fn table_line_display_matches_render_line() {
        let t = TableLine::new(0, 1024, Target::Linear { device: DevId::new(252, 5), offset_sectors: 5 });
        assert_eq!(t.to_string(), "0 1024 linear 252:5 5");
        // A no-param target renders without a trailing space.
        assert_eq!(TableLine::new(0, 8, Target::Zero).to_string(), "0 8 zero");
    }

    #[test]
    fn thin_pool_builder_matches_struct_literal() {
        let built = Target::thin_pool(DevId::new(252, 1), DevId::new(252, 2), 128, 0)
            .no_discard_passdown(true)
            .error_if_no_space(true)
            .build();
        let literal = Target::ThinPool {
            metadata: DevId::new(252, 1),
            data: DevId::new(252, 2),
            data_block_size_sectors: 128,
            low_water_mark_blocks: 0,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: true,
            read_only: false,
            error_if_no_space: true,
        };
        assert_eq!(built, literal);
    }

    #[test]
    fn writecache_and_integrity_builders_match_struct_literals() {
        let wc = Target::writecache(WritecacheKind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(90)
            .build();
        assert_eq!(
            wc,
            Target::Writecache {
                kind: WritecacheKind::Ssd,
                origin: DevId::new(252, 1),
                cache: DevId::new(252, 2),
                block_size: 4096,
                high_watermark_percent: Some(90),
                low_watermark_percent: None,
            }
        );

        let ig = Target::integrity(DevId::new(252, 1), 0, IntegrityMode::Direct)
            .internal_hash("sha256")
            .allow_discards(true)
            .build();
        assert_eq!(
            ig,
            Target::Integrity {
                device: DevId::new(252, 1),
                reserved_sectors: 0,
                tag_size: None,
                mode: IntegrityMode::Direct,
                internal_hash: Some("sha256".into()),
                allow_discards: true,
            }
        );
    }

    #[test]
    fn raid_device_pair_constructors() {
        assert_eq!(
            RaidDevicePair::data_only(DevId::new(252, 1)),
            RaidDevicePair { metadata: None, data: DevId::new(252, 1) }
        );
        assert_eq!(
            RaidDevicePair::new(Some(DevId::new(252, 2)), DevId::new(252, 3)),
            RaidDevicePair { metadata: Some(DevId::new(252, 2)), data: DevId::new(252, 3) }
        );
    }
}
