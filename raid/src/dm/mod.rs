// SPDX-License-Identifier: Apache-2.0

//! The `raid` target: software RAID over a set of devices, bridging to the
//! kernel's MD raid personalities.

use std::fmt::{self, Write as _};
use std::io;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::TargetEndpoint;
use devmap_core::{Fraction, ParseError, Target as DmTarget};

/// One `(metadata device, data device)` pair of a [`Target`] mapping.
/// `metadata` of `None` renders as `-` (no dedicated metadata device
/// for that slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePair {
    /// Optional dedicated metadata device for this slot; `None` renders as
    /// `-` (no separate metadata device).
    pub metadata: Option<DevId>,
    /// The data device for this slot.
    pub data: DevId,
}

impl DevicePair {
    /// A pair with a dedicated metadata device.
    #[must_use]
    pub fn new(metadata: Option<DevId>, data: DevId) -> Self {
        Self { metadata, data }
    }

    /// A pair with no dedicated metadata device (renders `-` for
    /// metadata).
    #[must_use]
    pub fn data_only(data: DevId) -> Self {
        Self {
            metadata: None,
            data,
        }
    }
}

/// [`Target`]'s raid level. `Raid5`/`Raid6` use the conventional default
/// parity layouts (`raid5_ls`, `raid6_zr`); for other layout suffixes
/// (`_la`/`_ra`/`_rs`/`_n`, ...) use a user-defined target.
/// Parsing accepts only the kernel names represented by these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Type {
    /// Striping with no redundancy.
    Raid0,
    /// Mirroring across all devices.
    Raid1,
    /// Striping with a dedicated parity device.
    Raid4,
    /// Striping with distributed single parity.
    Raid5,
    /// Striping with distributed double parity.
    Raid6,
    /// Striped mirrors (combined RAID1 and RAID0).
    Raid10,
}

impl FromStr for Type {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raid0" => Ok(Self::Raid0),
            "raid1" => Ok(Self::Raid1),
            "raid4" => Ok(Self::Raid4),
            "raid5_ls" => Ok(Self::Raid5),
            "raid6_zr" => Ok(Self::Raid6),
            "raid10" => Ok(Self::Raid10),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raid0 => "raid0",
            Self::Raid1 => "raid1",
            Self::Raid4 => "raid4",
            Self::Raid5 => "raid5_ls",
            Self::Raid6 => "raid6_zr",
            Self::Raid10 => "raid10",
        })
    }
}

/// Software RAID, bridging to the kernel's MD raid personalities. Only
/// the mandatory `chunk_size` raid parameter is exposed; sync control,
/// rebuild indices, and journal devices are locked out.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
// `raid_type` reads redundantly against the `Target` struct name, but it is
// the natural term for the field and its public accessor.
#[allow(clippy::struct_field_names)]
pub struct Target {
    raid_type: Type,
    chunk_size_sectors: u64,
    devices: Vec<DevicePair>,
}
impl Target {
    /// Construct a [`Target`].
    ///
    /// For [`Type::Raid1`] the kernel ignores the chunk size, so any
    /// argument is coerced to `0`.
    #[must_use]
    pub fn new(raid_type: Type, chunk_size_sectors: u64, devices: Vec<DevicePair>) -> Self {
        let chunk_size_sectors = if raid_type == Type::Raid1 {
            // raid1 has no stripes; the kernel ignores (and rejects a
            // non-zero) chunk size, so normalize to 0.
            0
        } else {
            chunk_size_sectors
        };
        Target {
            raid_type,
            chunk_size_sectors,
            devices,
        }
    }

    /// The raid level.
    #[must_use]
    pub fn raid_type(&self) -> Type {
        self.raid_type
    }
    /// The chunk size in sectors (`0` for raid1).
    #[must_use]
    pub fn chunk_size_sectors(&self) -> u64 {
        self.chunk_size_sectors
    }
    /// The device pairs backing this mapping.
    #[must_use]
    pub fn devices(&self) -> &[DevicePair] {
        &self.devices
    }
}
impl DmTarget for Target {
    const NAME: &'static str = "raid";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `<chunk_size>` is a bare positional number, not a
        // `chunk_size <value>` keyword pair — confirmed against
        // dm-raid.c's `parse_raid_params`. `#raid_params` is therefore 1.
        write!(
            f,
            "{} 1 {} {}",
            self.raid_type,
            self.chunk_size_sectors,
            self.devices.len()
        )?;
        for pair in &self.devices {
            match pair.metadata {
                Some(metadata) => write!(f, " {metadata}")?,
                None => f.write_str(" -")?,
            }
            write!(f, " {}", pair.data)?;
        }
        Ok(())
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let raid_type = fields.next().ok_or(ParseError)?.parse()?;
        // `Target` renders exactly one raid parameter, the chunk size. A
        // larger count means the table carries sync control, rebuild
        // indices, or a journal device, none of which this type holds.
        if fields.next().ok_or(ParseError)?.parse::<usize>()? != 1 {
            return Err(ParseError);
        }
        // Built field-by-field rather than through `Target::new`, which
        // coerces raid1's chunk size to 0 — a read must report what the
        // kernel said, not what a constructor would have normalized.
        let chunk_size_sectors = fields.next().ok_or(ParseError)?.parse()?;
        let count: usize = fields.next().ok_or(ParseError)?.parse()?;
        let mut devices = Vec::new();
        for _ in 0..count {
            let metadata = match fields.next().ok_or(ParseError)? {
                "-" => None,
                token => Some(token.parse()?),
            };
            devices.push(DevicePair {
                metadata,
                data: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            });
        }
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Target {
            raid_type,
            chunk_size_sectors,
            devices,
        })
    }
}

/// The state of one slot in a [`Target`] array, as the status line's
/// per-device health characters report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeviceHealth {
    /// Alive and in sync (`A`).
    InSync,
    /// Alive but not yet in sync — rebuilding or newly added (`a`).
    OutOfSync,
    /// Failed (`D`).
    Dead,
    /// No device in this slot (`-`).
    Missing,
}

impl fmt::Display for DeviceHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InSync => "A",
            Self::OutOfSync => "a",
            Self::Dead => "D",
            Self::Missing => "-",
        })
    }
}

impl TryFrom<char> for DeviceHealth {
    type Error = ParseError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        match c {
            'A' => Ok(DeviceHealth::InSync),
            'a' => Ok(DeviceHealth::OutOfSync),
            'D' => Ok(DeviceHealth::Dead),
            '-' => Ok(DeviceHealth::Missing),
            _ => Err(ParseError),
        }
    }
}

impl FromStr for DeviceHealth {
    type Err = ParseError;

    /// Parses exactly one health character, rejecting empty or longer strings.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let health = Self::try_from(chars.next().ok_or(ParseError)?)?;
        if chars.next().is_some() {
            return Err(ParseError);
        }
        Ok(health)
    }
}

/// What a [`Target`] array's sync thread is currently doing.
///
/// Encoded using the lowercase kernel action name; unknown names are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncAction {
    /// Sync is frozen by request.
    Frozen,
    /// Reshaping to a new layout, device count, or chunk size.
    Reshape,
    /// Resynchronizing redundancy after an unclean shutdown.
    Resync,
    /// Reading everything to count mismatches, without fixing them.
    Check,
    /// Reading everything and repairing mismatches.
    Repair,
    /// Rebuilding a replaced or re-added device.
    Recover,
    /// Nothing in progress.
    Idle,
    /// The kernel could not determine the state.
    Undef,
}

impl fmt::Display for SyncAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SyncAction::Frozen => "frozen",
            SyncAction::Reshape => "reshape",
            SyncAction::Resync => "resync",
            SyncAction::Check => "check",
            SyncAction::Repair => "repair",
            SyncAction::Recover => "recover",
            SyncAction::Idle => "idle",
            SyncAction::Undef => "undef",
        })
    }
}

impl FromStr for SyncAction {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "frozen" => Ok(SyncAction::Frozen),
            "reshape" => Ok(SyncAction::Reshape),
            "resync" => Ok(SyncAction::Resync),
            "check" => Ok(SyncAction::Check),
            "repair" => Ok(SyncAction::Repair),
            "recover" => Ok(SyncAction::Recover),
            "idle" => Ok(SyncAction::Idle),
            "undef" => Ok(SyncAction::Undef),
            _ => Err(ParseError),
        }
    }
}

/// [`Target`]'s runtime status: per-device health, sync progress, and the
/// integrity-check result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Info {
    /// The kernel's raid personality name, e.g. `raid1` or `raid6_zr`.
    /// A string rather than [`Type`] because the kernel reports every
    /// layout it supports, including ones [`Type`] cannot express.
    pub raid_type: String,
    /// Health of each slot, in array order.
    pub devices: Vec<DeviceHealth>,
    /// Sectors of `sync_total` already synced.
    pub sync_progress: u64,
    /// Sectors that a full sync covers.
    pub sync_total: u64,
    /// What the sync thread is doing.
    pub sync_action: SyncAction,
    /// Mismatched sectors found by the last `check`. Only meaningful
    /// after one has run.
    pub mismatches: u64,
    /// The data offset on each member device, which a reshape moves.
    pub data_offset: u64,
    /// The write-journal device's health, or `None` when the array has no
    /// journal — which the kernel renders as `-`.
    pub journal: Option<DeviceHealth>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.raid_type, self.devices.len())?;
        f.write_char(' ')?;
        for health in &self.devices {
            write!(f, "{health}")?;
        }
        write!(
            f,
            " {} {} {} {} ",
            Fraction::from((self.sync_progress, self.sync_total)),
            self.sync_action,
            self.mismatches,
            self.data_offset
        )?;
        match self.journal {
            Some(health) => write!(f, "{health}"),
            None => f.write_char('-'),
        }
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let raid_type = fields.next().ok_or(ParseError)?.to_owned();
        let count: usize = fields.next().ok_or(ParseError)?.parse()?;
        // One health character per slot, concatenated into a single
        // token, so its length must match the count read above.
        let health = fields.next().ok_or(ParseError)?;
        if health.chars().count() != count {
            return Err(ParseError);
        }
        let devices = health
            .chars()
            .map(DeviceHealth::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let (sync_progress, sync_total) = fields
            .next()
            .ok_or(ParseError)?
            .parse::<Fraction<u64>>()?
            .into();
        let sync_action = fields.next().ok_or(ParseError)?.parse()?;
        let mismatches = fields.next().ok_or(ParseError)?.parse()?;
        let data_offset = fields.next().ok_or(ParseError)?.parse()?;
        let journal = match fields.next().ok_or(ParseError)? {
            "-" => None,
            other => Some(other.parse()?),
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info {
            raid_type,
            devices,
            sync_progress,
            sync_total,
            sync_action,
            mismatches,
            data_offset,
            journal,
        })
    }
}

/// Messages to a live [`Target`] array, via
/// a backend's typed target endpoint. These drive the sync thread;
/// its progress shows up in [`Info::sync_action`].
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `idle` — stop the running sync thread.
    fn idle(&self) -> io::Result<()> {
        self.message("idle").map(drop)
    }

    /// `frozen` — freeze sync activity until told otherwise.
    fn frozen(&self) -> io::Result<()> {
        self.message("frozen").map(drop)
    }

    /// `resync` — (re)start a resync of the array's redundancy.
    fn resync(&self) -> io::Result<()> {
        self.message("resync").map(drop)
    }

    /// `recover` — (re)start recovery onto a replaced or added device.
    fn recover(&self) -> io::Result<()> {
        self.message("recover").map(drop)
    }

    /// `check` — scrub the array, counting mismatches without fixing them
    /// (see [`Info::mismatches`]).
    fn check(&self) -> io::Result<()> {
        self.message("check").map(drop)
    }

    /// `repair` — scrub the array and repair any mismatches found.
    fn repair(&self) -> io::Result<()> {
        self.message("repair").map(drop)
    }
}
impl<T: TargetEndpoint<Target = Target> + ?Sized> Commands for T {}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: DmTarget + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    #[test]
    fn raid_renders_type_chunk_size_and_device_pairs() {
        // raid1 ignores chunk size: the argument is coerced to 0.
        let t = Target::new(
            Type::Raid1,
            128,
            vec![
                DevicePair::new(None, DevId::new(252, 1).unwrap()),
                DevicePair::new(
                    Some(DevId::new(252, 2).unwrap()),
                    DevId::new(252, 3).unwrap(),
                ),
            ],
        );
        assert_eq!(
            line(0, 1_048_576, &t),
            "0 1048576 raid raid1 1 0 2 - 252:1 252:2 252:3"
        );
    }

    fn devs(n: u32) -> Vec<DevicePair> {
        (0..n)
            .map(|i| DevicePair::data_only(DevId::new(252, i).unwrap()))
            .collect()
    }

    #[test]
    fn raid_renders_each_type_token() {
        // raid5/raid6 render the kernel's default layout suffix, not a bare name.
        for (ty, token, n) in [
            (Type::Raid0, "raid0", 1),
            (Type::Raid4, "raid4", 2),
            (Type::Raid5, "raid5_ls", 2),
            (Type::Raid6, "raid6_zr", 3),
            (Type::Raid10, "raid10", 2),
        ] {
            let t = Target::new(ty, 8, devs(n));
            assert!(
                line(0, 1024, &t).contains(&format!("raid {token} 1 8 ")),
                "{token}"
            );
        }
    }

    #[test]
    fn raid_display_from_str_round_trips_each_type() {
        for (ty, n) in [
            (Type::Raid0, 1),
            (Type::Raid1, 2),
            (Type::Raid4, 2),
            (Type::Raid5, 2),
            (Type::Raid6, 3),
            (Type::Raid10, 2),
        ] {
            let original = Target::new(ty, 8, devs(n));
            assert_eq!(
                original.to_string().parse::<Target>().as_ref(),
                Ok(&original)
            );
        }
    }

    #[test]
    fn raid_display_from_str_round_trips_metadata_pairs() {
        let original = Target::new(
            Type::Raid1,
            0,
            vec![
                DevicePair::data_only(DevId::new(252, 1).unwrap()),
                DevicePair::new(
                    Some(DevId::new(252, 2).unwrap()),
                    DevId::new(252, 3).unwrap(),
                ),
            ],
        );
        assert_eq!(
            original.to_string().parse::<Target>().as_ref(),
            Ok(&original)
        );
    }

    #[test]
    fn raid_from_str_rejects_extra_raid_params() {
        // `sync` and `rebuild <n>` are real dm-raid parameters this type
        // doesn't render.
        assert!("raid1 2 sync 0 1 - 252:1".parse::<Target>().is_err());
        assert!("raid1 0 1 - 252:1".parse::<Target>().is_err());
    }

    #[test]
    fn raid_from_str_rejects_layouts_outside_the_type_enum() {
        assert!("raid5_ra 1 8 2 - 252:1 - 252:2".parse::<Target>().is_err());
        assert!(
            "raid6_nc 1 8 3 - 252:1 - 252:2 - 252:3"
                .parse::<Target>()
                .is_err()
        );
    }

    #[test]
    fn raid_from_str_rejects_a_count_disagreeing_with_the_pairs() {
        assert!("raid1 1 0 3 - 252:1 - 252:2".parse::<Target>().is_err());
        assert!("raid1 1 0 1 - 252:1 - 252:2".parse::<Target>().is_err());
    }

    #[test]
    fn raid_from_str_reports_a_raid1_chunk_size_the_kernel_gave() {
        // `Target::new` normalizes raid1's chunk size to 0; a read must not
        // apply that same coercion, or it would misreport the table.
        let parsed: Target = "raid1 1 8 1 - 252:1".parse().unwrap();
        assert_eq!(parsed.chunk_size_sectors(), 8);
        assert_eq!(parsed.to_string(), "raid1 1 8 1 - 252:1");
    }

    #[test]
    fn raid_device_pair_constructors() {
        assert_eq!(
            DevicePair::data_only(DevId::new(252, 1).unwrap()),
            DevicePair {
                metadata: None,
                data: DevId::new(252, 1).unwrap()
            }
        );
        assert_eq!(
            DevicePair::new(
                Some(DevId::new(252, 2).unwrap()),
                DevId::new(252, 3).unwrap()
            ),
            DevicePair {
                metadata: Some(DevId::new(252, 2).unwrap()),
                data: DevId::new(252, 3).unwrap()
            }
        );
    }
}
