// SPDX-License-Identifier: Apache-2.0

//! The snapshot targets: `snapshot-origin`, `snapshot`, and
//! `snapshot-merge`, providing copy-on-write snapshots of a device.

use std::fmt;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::{Fraction, NoInfo, ParseError, Target};

/// Marks a device as the origin of a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotOriginTarget {
    /// The device being snapshotted.
    pub origin: DevId,
}
impl Target for SnapshotOriginTarget {
    const NAME: &'static str = "snapshot-origin";
    type Table = Self;
    type Info = NoInfo;
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

/// A copy-on-write snapshot of an origin device. Always persistent with
/// overflow support ("PO").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotTarget {
    /// The device being snapshotted.
    pub origin: DevId,
    /// The copy-on-write store holding changed chunks.
    pub cow: DevId,
    /// Copy-on-write chunk size, in 512-byte sectors.
    pub chunk_size_sectors: u32,
}
impl Target for SnapshotTarget {
    const NAME: &'static str = "snapshot";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for SnapshotTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} PO {}",
            self.origin, self.cow, self.chunk_size_sectors
        )
    }
}

impl FromStr for SnapshotTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let origin = fields.next().ok_or(ParseError)?.parse::<DevId>()?;
        let cow = fields.next().ok_or(ParseError)?.parse::<DevId>()?;
        // This type is always persistent-with-overflow. The kernel's other
        // persistence modes ("P" and the transient "N") are real tables it
        // cannot hold, so reject rather than misreport them as "PO".
        if fields.next().ok_or(ParseError)? != "PO" {
            return Err(ParseError);
        }
        let chunk_size_sectors = fields.next().ok_or(ParseError)?.parse()?;
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(SnapshotTarget {
            origin,
            cow,
            chunk_size_sectors,
        })
    }
}

/// Merges an existing persistent [`SnapshotTarget`]'s copy-on-write data back
/// into its origin. The mapping is identical to [`SnapshotTarget`]'s; only the
/// kernel target name differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotMergeTarget(pub SnapshotTarget);
impl Target for SnapshotMergeTarget {
    const NAME: &'static str = "snapshot-merge";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for SnapshotMergeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for SnapshotMergeTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(SnapshotMergeTarget)
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

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: Target + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    fn snapshot(chunk_size_sectors: u32) -> SnapshotTarget {
        SnapshotTarget {
            origin: DevId::new(252, 1).unwrap(),
            cow: DevId::new(252, 2).unwrap(),
            chunk_size_sectors,
        }
    }

    #[test]
    fn snapshot_renders_with_po_persistence() {
        let t = snapshot(8);
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot 252:1 252:2 PO 8");
    }

    #[test]
    fn snapshot_origin_renders_device_only() {
        let t = SnapshotOriginTarget {
            origin: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-origin 252:1");
    }

    #[test]
    fn snapshot_merge_renders_like_snapshot_with_po() {
        let t = SnapshotMergeTarget(snapshot(8));
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-merge 252:1 252:2 PO 8");
    }

    #[test]
    fn snapshot_and_merge_display_from_str_round_trip() {
        let original = snapshot(16);
        assert_eq!(original.to_string().parse::<SnapshotTarget>(), Ok(original));
        let original = SnapshotMergeTarget(original);
        assert_eq!(
            original.to_string().parse::<SnapshotMergeTarget>(),
            Ok(original)
        );
    }

    #[test]
    fn snapshot_from_str_rejects_other_persistence_modes() {
        // "P" (persistent, no overflow) and "N" (transient) are real
        // dm-snapshot tables this type cannot hold.
        assert!("252:1 252:2 P 8".parse::<SnapshotTarget>().is_err());
        assert!("252:1 252:2 N 8".parse::<SnapshotTarget>().is_err());
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
}
