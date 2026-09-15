// SPDX-License-Identifier: Apache-2.0

//! The `era` target: tracks which blocks of an origin device have changed
//! since a given "era", for incremental backup.

use std::fmt;
use std::io;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::TargetEndpoint;
use devmap_core::{Fraction, ParseError, Target as DmTarget};

/// Tracks which blocks of `origin` have changed since which "era", for
/// incremental backup. Target rollover/snapshot control is message-driven
/// — see [`devmap_core::TargetEndpoint::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// Device holding the era metadata (the change map).
    pub metadata: DevId,
    /// The origin device whose changes are tracked.
    pub origin: DevId,
    /// Tracking granularity, in 512-byte sectors per block.
    pub block_size: u32,
}
impl DmTarget for Target {
    const NAME: &'static str = "era";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.metadata, self.origin, self.block_size)
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let target = Target {
            metadata: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            origin: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            block_size: fields.next().ok_or(ParseError)?.parse()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(target)
    }
}

/// [`Target`]'s runtime status: metadata usage, and which era writes are
/// currently being stamped with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// The metadata block size in 512-byte sectors. The kernel fixes its
    /// metadata block size at 4 KiB, so this is always 8.
    pub metadata_block_size_sectors: u32,
    /// Metadata blocks in use.
    pub used_metadata_blocks: u64,
    /// Metadata blocks in total.
    pub total_metadata_blocks: u64,
    /// The era writes are currently stamped with, advanced by the
    /// `checkpoint` message.
    pub current_era: u32,
    /// The block holding a metadata snapshot taken with
    /// `take_metadata_snap`, or `None` when none is held.
    pub held_metadata_root: Option<u64>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.metadata_block_size_sectors,
            Fraction::from((self.used_metadata_blocks, self.total_metadata_blocks)),
            self.current_era
        )?;
        match self.held_metadata_root {
            Some(block) => write!(f, " {block}"),
            None => f.write_str(" -"),
        }
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let metadata_block_size_sectors = fields.next().ok_or(ParseError)?.parse()?;
        let (used_metadata_blocks, total_metadata_blocks) = fields
            .next()
            .ok_or(ParseError)?
            .parse::<Fraction<u64>>()?
            .into();
        let current_era = fields.next().ok_or(ParseError)?.parse()?;
        let held_metadata_root = match fields.next().ok_or(ParseError)? {
            "-" => None,
            block => Some(block.parse()?),
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info {
            metadata_block_size_sectors,
            used_metadata_blocks,
            total_metadata_blocks,
            current_era,
            held_metadata_root,
        })
    }
}

/// Messages to a live [`Target`], via
/// a backend's typed target endpoint.
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `checkpoint` — begin a new era, so subsequent writes are stamped
    /// with a higher era number.
    fn checkpoint(&self) -> io::Result<()> {
        self.message("checkpoint").map(drop)
    }

    /// `take_metadata_snap` — pin a metadata snapshot so userspace can read
    /// the change map offline.
    fn take_metadata_snap(&self) -> io::Result<()> {
        self.message("take_metadata_snap").map(drop)
    }

    /// `drop_metadata_snap` — release the pinned metadata snapshot.
    fn drop_metadata_snap(&self) -> io::Result<()> {
        self.message("drop_metadata_snap").map(drop)
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
    fn era_renders_metadata_origin_and_block_size() {
        let t = Target {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 era 252:1 252:2 128");
    }

    #[test]
    fn era_display_from_str_round_trips() {
        let original = Target {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }
}
