// SPDX-License-Identifier: Apache-2.0

//! The snapshot targets: `snapshot-origin`, `snapshot`, and
//! `snapshot-merge`, providing copy-on-write snapshots of a device.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{ParseError, RawInfo, Target, parse_device};

/// Marks a device as the origin of a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Origin {
    /// The device being snapshotted.
    pub origin: DevId,
}
impl Target for Origin {
    const NAME: &'static str = "snapshot-origin";
    type Info = RawInfo;
}
impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.origin)
    }
}
impl FromStr for Origin {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split_whitespace();
        let origin = it.next().and_then(parse_device).ok_or(ParseError)?;
        if it.next().is_some() {
            return Err(ParseError);
        }
        Ok(Origin { origin })
    }
}

/// A copy-on-write snapshot of an origin device. Always persistent with
/// overflow support ("PO").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Snapshot {
    /// The device being snapshotted.
    pub origin: DevId,
    /// The copy-on-write store holding changed chunks.
    pub cow: DevId,
    /// Copy-on-write chunk size, in 512-byte sectors.
    pub chunk_size_sectors: u32,
}
impl Target for Snapshot {
    const NAME: &'static str = "snapshot";
    type Info = RawInfo;
}
impl fmt::Display for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} PO {}",
            self.origin, self.cow, self.chunk_size_sectors
        )
    }
}

/// Merges an existing persistent [`Snapshot`]'s copy-on-write data back
/// into its origin. The mapping is identical to [`Snapshot`]'s; only the
/// kernel target name differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Merge(pub Snapshot);
impl Target for Merge {
    const NAME: &'static str = "snapshot-merge";
    type Info = RawInfo;
}
impl fmt::Display for Merge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {params}", T::NAME)
        }
    }

    fn snapshot(chunk_size_sectors: u32) -> Snapshot {
        Snapshot {
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
        let t = Origin {
            origin: DevId::new(252, 1).unwrap(),
        };
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-origin 252:1");
    }

    #[test]
    fn snapshot_merge_renders_like_snapshot_with_po() {
        let t = Merge(snapshot(8));
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-merge 252:1 252:2 PO 8");
    }

    #[test]
    fn snapshot_origin_from_str_rejects_trailing_tokens() {
        assert!("252:1 extra".parse::<Origin>().is_err());
    }

    #[test]
    fn snapshot_origin_display_from_str_round_trips() {
        let original = Origin {
            origin: DevId::new(252, 7).unwrap(),
        };
        let params = original.to_string();
        assert_eq!(params.parse::<Origin>(), Ok(original));
    }
}
