// SPDX-License-Identifier: Apache-2.0

//! The snapshot targets: `snapshot-origin`, `snapshot`, and
//! `snapshot-merge`, providing copy-on-write snapshots of a device.

use std::fmt;
use std::num::NonZero;
use std::str::FromStr;

use super::{Empty, EncodeError, Target, Version};
use crate::table::{InfoMode, TableMode};
use crate::target::Parse;
use crate::{DevId, ParseError};

/// Two values encoded as `a/b` in snapshot status text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Fraction<T>(T, T);

impl<T: FromStr> FromStr for Fraction<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first, second) = s.split_once('/').ok_or(ParseError)?;
        Ok(Self(
            first.parse().map_err(|_| ParseError)?,
            second.parse().map_err(|_| ParseError)?,
        ))
    }
}

impl<T: fmt::Display> fmt::Display for Fraction<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

impl<T> From<(T, T)> for Fraction<T> {
    fn from((first, second): (T, T)) -> Self {
        Self(first, second)
    }
}

impl<T> From<Fraction<T>> for (T, T) {
    fn from(value: Fraction<T>) -> Self {
        (value.0, value.1)
    }
}

/// Marks a device as the origin of a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotOriginTarget {
    /// The device being snapshotted.
    pub origin: DevId,
}
impl Target for SnapshotOriginTarget {
    const NAME: &'static str = "snapshot-origin";
    type Table = Self;
    type Info = Empty;

    fn encode(&self, version: Version) -> Result<String, EncodeError> {
        if version.major != 1 {
            return Err(EncodeError { version });
        }
        Ok(self.to_string())
    }
}

impl Parse<TableMode> for SnapshotOriginTarget {
    type Error = ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        if version.major != 1 {
            return Err(ParseError);
        }
        let target: Self = text.parse()?;
        Ok(target)
    }
}
impl fmt::Display for SnapshotOriginTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.origin)
    }
}
impl FromStr for SnapshotOriginTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split_whitespace();
        let origin = it
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(ParseError)?;
        if it.next().is_some() {
            return Err(ParseError);
        }
        Ok(SnapshotOriginTarget { origin })
    }
}

/// A validated snapshot chunk size in 512-byte sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkSize(NonZero<u32>);

impl ChunkSize {
    const MAX_SECTORS: u32 = (i32::MAX as u32) >> 9;

    /// Validates a kernel snapshot chunk size.
    pub const fn new(sectors: NonZero<u32>) -> Option<Self> {
        if sectors.get().is_power_of_two() && sectors.get() <= Self::MAX_SECTORS {
            Some(Self(sectors))
        } else {
            None
        }
    }

    /// Returns the chunk size in 512-byte sectors.
    pub const fn sectors(self) -> NonZero<u32> {
        self.0
    }
}

impl fmt::Display for ChunkSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ChunkSize {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>()
            .ok()
            .and_then(NonZero::new)
            .and_then(Self::new)
            .ok_or(ParseError)
    }
}

/// Snapshot exception-store persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persistence {
    /// Persistent metadata without overflow reporting (`P`).
    Persistent,
    /// Persistent metadata with overflow reporting (`PO`).
    PersistentOverflow,
    /// In-memory metadata that does not survive reactivation (`N`).
    Transient,
}

impl fmt::Display for Persistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Persistent => "P",
            Self::PersistentOverflow => "PO",
            Self::Transient => "N",
        })
    }
}

impl FromStr for Persistence {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P" => Ok(Self::Persistent),
            "PO" => Ok(Self::PersistentOverflow),
            "N" => Ok(Self::Transient),
            _ => Err(ParseError),
        }
    }
}

/// Optional snapshot discard behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SnapshotFeatures {
    discard_zeroes_cow: bool,
    discard_passdown_origin: bool,
}

impl SnapshotFeatures {
    /// No optional behavior.
    pub const NONE: Self = Self {
        discard_zeroes_cow: false,
        discard_passdown_origin: false,
    };

    /// Constructs a valid feature combination.
    pub const fn new(discard_zeroes_cow: bool, discard_passdown_origin: bool) -> Option<Self> {
        if discard_passdown_origin && !discard_zeroes_cow {
            None
        } else {
            Some(Self {
                discard_zeroes_cow,
                discard_passdown_origin,
            })
        }
    }

    /// Whether full-chunk discards remove COW exceptions.
    pub const fn discard_zeroes_cow(self) -> bool {
        self.discard_zeroes_cow
    }

    /// Whether eligible discards pass through to the origin.
    pub const fn discard_passdown_origin(self) -> bool {
        self.discard_passdown_origin
    }
}

/// A copy-on-write snapshot of an origin device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotTarget {
    /// The device being snapshotted.
    pub origin: DevId,
    /// The copy-on-write store holding changed chunks.
    pub cow: DevId,
    /// Exception-store persistence mode.
    pub persistence: Persistence,
    /// Copy-on-write chunk size.
    pub chunk_size: ChunkSize,
    /// Optional discard behavior.
    pub features: SnapshotFeatures,
}

impl SnapshotTarget {
    /// Constructs a snapshot without optional discard behavior.
    pub const fn new(
        origin: DevId,
        cow: DevId,
        persistence: Persistence,
        chunk_size: ChunkSize,
    ) -> Self {
        Self {
            origin,
            cow,
            persistence,
            chunk_size,
            features: SnapshotFeatures::NONE,
        }
    }

    fn supports_version(&self, version: Version) -> bool {
        version.major == 1
            && (self.persistence != Persistence::PersistentOverflow
                || version >= Version::from([1, 15, 0]))
            && (self.features == SnapshotFeatures::NONE || version >= Version::from([1, 16, 0]))
    }
}
impl Target for SnapshotTarget {
    const NAME: &'static str = "snapshot";
    type Table = Self;
    type Info = Info;

    fn encode(&self, version: Version) -> Result<String, EncodeError> {
        if !self.supports_version(version) {
            return Err(EncodeError { version });
        }
        Ok(self.to_string())
    }
}

impl Parse<TableMode> for SnapshotTarget {
    type Error = ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        let target: Self = text.parse()?;
        if !target.supports_version(version) {
            return Err(ParseError);
        }
        Ok(target)
    }
}
impl fmt::Display for SnapshotTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.origin, self.cow, self.persistence, self.chunk_size
        )?;
        let count = usize::from(self.features.discard_zeroes_cow)
            + usize::from(self.features.discard_passdown_origin);
        if count != 0 {
            write!(f, " {count}")?;
            if self.features.discard_zeroes_cow {
                f.write_str(" discard_zeroes_cow")?;
            }
            if self.features.discard_passdown_origin {
                f.write_str(" discard_passdown_origin")?;
            }
        }
        Ok(())
    }
}

impl FromStr for SnapshotTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let origin = fields.next().ok_or(ParseError)?.parse::<DevId>()?;
        let cow = fields.next().ok_or(ParseError)?.parse::<DevId>()?;
        let persistence = fields.next().ok_or(ParseError)?.parse()?;
        let chunk_size = fields.next().ok_or(ParseError)?.parse()?;
        let mut zeroes = false;
        let mut passdown = false;
        if let Some(count) = fields.next() {
            let count: usize = count.parse()?;
            for _ in 0..count {
                match fields.next().ok_or(ParseError)? {
                    "discard_zeroes_cow" if !zeroes => zeroes = true,
                    "discard_passdown_origin" if !passdown => passdown = true,
                    _ => return Err(ParseError),
                }
            }
        }
        if fields.next().is_some() {
            return Err(ParseError);
        }
        let features = SnapshotFeatures::new(zeroes, passdown).ok_or(ParseError)?;
        Ok(SnapshotTarget {
            origin,
            cow,
            persistence,
            chunk_size,
            features,
        })
    }
}

/// Merges an existing persistent [`SnapshotTarget`]'s copy-on-write data back
/// into its origin. The mapping is identical to [`SnapshotTarget`]'s; only the
/// kernel target name differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotMergeTarget(SnapshotTarget);

impl TryFrom<SnapshotTarget> for SnapshotMergeTarget {
    type Error = ParseError;

    fn try_from(value: SnapshotTarget) -> Result<Self, Self::Error> {
        if value.persistence == Persistence::Transient {
            Err(ParseError)
        } else {
            Ok(Self(value))
        }
    }
}

impl SnapshotMergeTarget {
    /// Returns the persistent snapshot parameters used by the merge.
    pub const fn snapshot(self) -> SnapshotTarget {
        self.0
    }

    fn supports_version(&self, version: Version) -> bool {
        version.major == 1
            && (self.0.persistence != Persistence::PersistentOverflow
                || version >= Version::from([1, 4, 0]))
            && (self.0.features == SnapshotFeatures::NONE || version >= Version::from([1, 5, 0]))
    }
}
impl Target for SnapshotMergeTarget {
    const NAME: &'static str = "snapshot-merge";
    type Table = Self;
    type Info = Info;

    fn encode(&self, version: Version) -> Result<String, EncodeError> {
        if !self.supports_version(version) {
            return Err(EncodeError { version });
        }
        Ok(self.to_string())
    }
}

impl Parse<TableMode> for SnapshotMergeTarget {
    type Error = ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        let target: Self = text.parse()?;
        if !target.supports_version(version) {
            return Err(ParseError);
        }
        Ok(target)
    }
}
impl fmt::Display for SnapshotMergeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for SnapshotMergeTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<SnapshotTarget>()?.try_into()
    }
}

/// The runtime status of a [`SnapshotTarget`] or [`SnapshotMergeTarget`].
/// Both share the kernel's status callback.
///
/// An enum rather than a struct because the kernel does not pair usage
/// with a health flag: when the snapshot is unusable it emits a bare
/// keyword *instead of* every numeric field. A struct would have to
/// invent numbers for those states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Info {
    /// The snapshot is live, with copy-on-write store usage.
    Usage {
        /// Sectors of the store allocated to exceptions.
        allocated_sectors: u64,
        /// Sectors in the store in total. When `allocated` reaches this
        /// the snapshot overflows and is invalidated.
        total_sectors: u64,
        /// Sectors of the store spent on its own metadata, counted within
        /// `allocated_sectors`.
        metadata_sectors: u64,
    },

    /// The snapshot is invalid and cannot be recovered.
    Invalid,

    /// A [`SnapshotMergeTarget`] back into the origin failed partway.
    MergeFailed,

    /// The store filled and the snapshot was dropped.
    Overflow,

    /// The exception store does not report usage, so the kernel has
    /// nothing to say about it.
    Unknown,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Info::Usage {
                allocated_sectors,
                total_sectors,
                metadata_sectors,
            } => write!(
                f,
                "{} {metadata_sectors}",
                Fraction::from((*allocated_sectors, *total_sectors))
            ),
            Info::Invalid => f.write_str("Invalid"),
            Info::MergeFailed => f.write_str("Merge failed"),
            Info::Overflow => f.write_str("Overflow"),
            Info::Unknown => f.write_str("Unknown"),
        }
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The sentinels replace the entire line, and "Merge failed" is two
        // tokens, so match the trimmed line before tokenizing at all.
        match s.trim() {
            "Invalid" => return Ok(Info::Invalid),
            "Merge failed" => return Ok(Info::MergeFailed),
            "Overflow" => return Ok(Info::Overflow),
            "Unknown" => return Ok(Info::Unknown),
            _ => {}
        }
        let mut fields = s.split_whitespace();
        let (allocated_sectors, total_sectors) = fields
            .next()
            .ok_or(ParseError)?
            .parse::<Fraction<u64>>()?
            .into();
        let metadata_sectors = fields.next().ok_or(ParseError)?.parse()?;
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info::Usage {
            allocated_sectors,
            total_sectors,
            metadata_sectors,
        })
    }
}

impl Parse<InfoMode> for Info {
    type Error = ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        if version.major != 1 {
            return Err(ParseError);
        }
        let info: Self = text.parse()?;
        if info == Self::Overflow && version < Version::from([1, 4, 0]) {
            return Err(ParseError);
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractions_round_trip_without_interpreting_their_values() {
        for values in [(0, 0), (0, 1), (12, 8), (9, 10), (u32::MAX, u32::MAX)] {
            let fraction = Fraction::from(values);
            let text = fraction.to_string();
            assert_eq!(text, format!("{}/{}", values.0, values.1));
            assert_eq!(text.parse::<Fraction<u32>>().unwrap(), fraction);
            assert_eq!(<(u32, u32)>::from(fraction), values);
        }

        for values in [(0, 0), (12, 8), (u64::MAX, u64::MAX)] {
            let fraction = Fraction::from(values);
            let text = fraction.to_string();
            assert_eq!(text, format!("{}/{}", values.0, values.1));
            assert_eq!(text.parse::<Fraction<u64>>().unwrap(), fraction);
            assert_eq!(<(u64, u64)>::from(fraction), values);
        }
    }

    #[test]
    fn integer_fractions_reject_malformed_fields_and_overflow() {
        for text in [
            "", "1", "/", "/1", "1/", "1/2/3", "x/2", "1/x", "-1/2", "1/-2", " 1/2", "1/2 ",
            "1 /2", "1/ 2", "1\n/2", "1/2\0",
        ] {
            assert_eq!(text.parse::<Fraction<u32>>(), Err(ParseError), "{text:?}");
            assert_eq!(text.parse::<Fraction<u64>>(), Err(ParseError), "{text:?}");
        }

        for text in ["4294967296/0", "0/4294967296"] {
            assert_eq!(text.parse::<Fraction<u32>>(), Err(ParseError));
            assert!(text.parse::<Fraction<u64>>().is_ok());
        }

        for text in ["18446744073709551616/0", "0/18446744073709551616"] {
            assert_eq!(text.parse::<Fraction<u64>>(), Err(ParseError));
        }
    }

    #[test]
    fn fraction_components_use_their_own_parser_and_formatter() {
        let fraction: Fraction<u32> = "+0012/0064".parse().unwrap();
        assert_eq!(fraction.to_string(), "12/64");
        let signed: Fraction<i64> = "-3/0".parse().unwrap();
        assert_eq!(<(i64, i64)>::from(signed), (-3, 0));
    }

    fn line<T: Target>(start: u64, length: u64, value: &T, version: Version) -> String {
        let parameters = value.encode(version).unwrap();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    fn snapshot(persistence: Persistence) -> SnapshotTarget {
        SnapshotTarget::new(
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            persistence,
            ChunkSize::new(NonZero::new(8).unwrap()).unwrap(),
        )
    }

    #[test]
    fn snapshot_renders_with_po_persistence() {
        let t = snapshot(Persistence::PersistentOverflow);
        assert_eq!(
            line(0, 1024, &t, Version::from([1, 16, 0])),
            "0 1024 snapshot 252:1 252:2 PO 8"
        );
    }

    #[test]
    fn snapshot_origin_renders_device_only() {
        let t = SnapshotOriginTarget {
            origin: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(
            line(0, 1024, &t, Version::from([1, 9, 0])),
            "0 1024 snapshot-origin 252:1"
        );
    }

    #[test]
    fn snapshot_merge_renders_like_snapshot_with_po() {
        let t = SnapshotMergeTarget::try_from(snapshot(Persistence::PersistentOverflow)).unwrap();
        assert_eq!(
            line(0, 1024, &t, Version::from([1, 5, 0])),
            "0 1024 snapshot-merge 252:1 252:2 PO 8"
        );
    }

    #[test]
    fn snapshot_and_merge_display_from_str_round_trip() {
        let original = snapshot(Persistence::Persistent);
        assert_eq!(original.to_string().parse::<SnapshotTarget>(), Ok(original));
        let original = SnapshotMergeTarget::try_from(original).unwrap();
        assert_eq!(
            original.to_string().parse::<SnapshotMergeTarget>(),
            Ok(original)
        );
    }

    #[test]
    fn snapshot_supports_every_persistence_and_discard_feature() {
        for line in [
            "252:1 252:2 P 8",
            "252:1 252:2 PO 8 1 discard_zeroes_cow",
            "252:1 252:2 N 8 2 discard_zeroes_cow discard_passdown_origin",
        ] {
            assert_eq!(line.parse::<SnapshotTarget>().unwrap().to_string(), line);
        }
        assert!("252:1 252:2 N 8".parse::<SnapshotMergeTarget>().is_err());
        assert!(
            "252:1 252:2 PO 8 1 discard_passdown_origin"
                .parse::<SnapshotTarget>()
                .is_err()
        );
    }

    #[test]
    fn snapshot_origin_from_str_rejects_trailing_tokens() {
        assert!("252:1 extra".parse::<SnapshotOriginTarget>().is_err());
    }

    #[test]
    fn snapshot_origin_display_from_str_round_trips() {
        let original = SnapshotOriginTarget {
            origin: DevId::new(252, 7).unwrap(),
        };
        let params = original.to_string();
        assert_eq!(params.parse::<SnapshotOriginTarget>(), Ok(original));
    }

    #[test]
    fn snapshot_versions_gate_overflow_and_discard_features() {
        let base = snapshot(Persistence::Persistent);
        let overflow = snapshot(Persistence::PersistentOverflow);
        let mut discard = base;
        discard.features = SnapshotFeatures::new(true, false).unwrap();

        for (target, before, minimum) in [
            (overflow, [1, 14, 0], [1, 15, 0]),
            (discard, [1, 15, 0], [1, 16, 0]),
        ] {
            let before = Version::from(before);
            let minimum = Version::from(minimum);
            assert_eq!(target.encode(before), Err(EncodeError { version: before }));
            assert!(target.encode(minimum).is_ok());

            let text = target.to_string();
            assert_eq!(
                <SnapshotTarget as Parse<TableMode>>::parse(&text, before),
                Err(ParseError)
            );
            assert_eq!(
                <SnapshotTarget as Parse<TableMode>>::parse(&text, minimum),
                Ok(target)
            );
        }

        assert!(base.encode(Version::from([1, 0, 0])).is_ok());
        assert!(base.encode(Version::from([2, 0, 0])).is_err());
    }

    #[test]
    fn merge_versions_use_their_own_feature_boundaries() {
        let overflow =
            SnapshotMergeTarget::try_from(snapshot(Persistence::PersistentOverflow)).unwrap();
        let mut discard = snapshot(Persistence::Persistent);
        discard.features = SnapshotFeatures::new(true, true).unwrap();
        let discard = SnapshotMergeTarget::try_from(discard).unwrap();

        for (target, before, minimum) in [
            (overflow, [1, 3, 0], [1, 4, 0]),
            (discard, [1, 4, 0], [1, 5, 0]),
        ] {
            let before = Version::from(before);
            let minimum = Version::from(minimum);
            assert_eq!(target.encode(before), Err(EncodeError { version: before }));
            assert!(target.encode(minimum).is_ok());

            let text = target.to_string();
            assert_eq!(
                <SnapshotMergeTarget as Parse<TableMode>>::parse(&text, before),
                Err(ParseError)
            );
            assert_eq!(
                <SnapshotMergeTarget as Parse<TableMode>>::parse(&text, minimum),
                Ok(target)
            );
        }
    }

    #[test]
    fn origin_and_info_reject_unknown_major_versions() {
        let origin = SnapshotOriginTarget {
            origin: DevId::new(252, 1).unwrap(),
        };
        let version = Version::from([2, 0, 0]);
        assert_eq!(origin.encode(version), Err(EncodeError { version }));
        assert_eq!(
            <SnapshotOriginTarget as Parse<TableMode>>::parse(&origin.to_string(), version),
            Err(ParseError)
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("Invalid", version),
            Err(ParseError)
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("Overflow", Version::from([1, 3, 0])),
            Err(ParseError)
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("Overflow", Version::from([1, 4, 0])),
            Ok(Info::Overflow)
        );
    }
}
