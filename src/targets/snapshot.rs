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
    const TYPE_NAME: &'static str = "snapshot-origin";
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
#[non_exhaustive]
pub struct Snapshot {
    origin: DevId,
    cow: DevId,
    chunk_size_sectors: u32,
}
impl Snapshot {
    /// Construct a [`Snapshot`].
    #[must_use]
    pub fn new(origin: DevId, cow: DevId, chunk_size_sectors: u32) -> Self {
        Snapshot {
            origin,
            cow,
            chunk_size_sectors,
        }
    }

    /// The device being snapshotted.
    #[must_use]
    pub fn origin(&self) -> DevId {
        self.origin
    }
    /// The copy-on-write store holding changed chunks.
    #[must_use]
    pub fn cow(&self) -> DevId {
        self.cow
    }
    /// Copy-on-write chunk size, in 512-byte sectors.
    #[must_use]
    pub fn chunk_size_sectors(&self) -> u32 {
        self.chunk_size_sectors
    }
}
impl Target for Snapshot {
    const TYPE_NAME: &'static str = "snapshot";
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
/// into its origin. Takes the same fields as [`Snapshot`] and is always
/// persistent with overflow support ("PO").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Merge {
    origin: DevId,
    cow: DevId,
    chunk_size_sectors: u32,
}
impl Merge {
    /// Construct a [`Merge`].
    #[must_use]
    pub fn new(origin: DevId, cow: DevId, chunk_size_sectors: u32) -> Self {
        Merge {
            origin,
            cow,
            chunk_size_sectors,
        }
    }

    /// The origin device to merge back into.
    #[must_use]
    pub fn origin(&self) -> DevId {
        self.origin
    }
    /// The copy-on-write store to merge from.
    #[must_use]
    pub fn cow(&self) -> DevId {
        self.cow
    }
    /// Copy-on-write chunk size, in 512-byte sectors.
    #[must_use]
    pub fn chunk_size_sectors(&self) -> u32 {
        self.chunk_size_sectors
    }
}
impl Target for Merge {
    const TYPE_NAME: &'static str = "snapshot-merge";
    type Info = RawInfo;
}
impl fmt::Display for Merge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} PO {}",
            self.origin, self.cow, self.chunk_size_sectors
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn snapshot_renders_with_po_persistence() {
        let t = Snapshot::new(DevId::new(252, 1), DevId::new(252, 2), 8);
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot 252:1 252:2 PO 8");
    }

    #[test]
    fn snapshot_origin_renders_device_only() {
        let t = Origin {
            origin: DevId::new(252, 1),
        };
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-origin 252:1");
    }

    #[test]
    fn snapshot_merge_renders_like_snapshot_with_po() {
        let t = Merge::new(DevId::new(252, 1), DevId::new(252, 2), 8);
        assert_eq!(line(0, 1024, &t), "0 1024 snapshot-merge 252:1 252:2 PO 8");
    }

    #[test]
    fn snapshot_origin_from_str_rejects_trailing_tokens() {
        assert!("252:1 extra".parse::<Origin>().is_err());
    }

    #[test]
    fn snapshot_origin_display_from_str_round_trips() {
        let original = Origin {
            origin: DevId::new(252, 7),
        };
        let params = original.to_string();
        assert_eq!(params.parse::<Origin>(), Ok(original));
    }
}
