// SPDX-License-Identifier: Apache-2.0

//! The `era` target: tracks which blocks of an origin device have changed
//! since a given "era", for incremental backup.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, Target};

/// Tracks which blocks of `origin` have changed since which "era", for
/// incremental backup. Era rollover/snapshot control is message-driven
/// — see [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Era {
    /// Device holding the era metadata (the change map).
    pub metadata: DevId,
    /// The origin device whose changes are tracked.
    pub origin: DevId,
    /// Tracking granularity, in 512-byte sectors per block.
    pub block_size: u32,
}
impl Target for Era {
    const NAME: &'static str = "era";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Era {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.metadata, self.origin, self.block_size)
    }
}
impl FromStr for Era {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let target = Era {
            metadata: p.device()?,
            origin: p.device()?,
            block_size: p.value()?,
        };
        p.end()?;
        Ok(target)
    }
}

/// [`Era`]'s runtime status: metadata usage, and which era writes are
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
            "{} {}/{} {}",
            self.metadata_block_size_sectors,
            self.used_metadata_blocks,
            self.total_metadata_blocks,
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
        let mut p = Params::new(s);
        let metadata_block_size_sectors = p.value()?;
        let (used_metadata_blocks, total_metadata_blocks) = p.fraction()?;
        let current_era = p.value()?;
        let held_metadata_root = match p.token()? {
            "-" => None,
            block => Some(block.parse().map_err(|_| ParseError)?),
        };
        p.end()?;
        Ok(Info {
            metadata_block_size_sectors,
            used_metadata_blocks,
            total_metadata_blocks,
            current_era,
            held_metadata_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    #[test]
    fn era_renders_metadata_origin_and_block_size() {
        let t = Era {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 era 252:1 252:2 128");
    }

    #[test]
    fn era_display_from_str_round_trips() {
        let original = Era {
            metadata: DevId::new(252, 1).unwrap(),
            origin: DevId::new(252, 2).unwrap(),
            block_size: 128,
        };
        assert_eq!(original.to_string().parse::<Era>(), Ok(original));
    }
}
