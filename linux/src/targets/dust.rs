// SPDX-License-Identifier: Apache-2.0

//! The `dust` target: injects read/write errors at chosen blocks for
//! fault-injection testing.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, Target};

/// Injects read/write errors at specific blocks, for fault-injection
/// testing. Bad-block management is message-driven — see
/// [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dust {
    /// The backing device.
    pub device: DevId,
    /// The starting offset in sectors.
    pub offset_sectors: u64,
    /// The block size in bytes.
    pub block_size: u32,
}
impl Target for Dust {
    const NAME: &'static str = "dust";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Dust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.device, self.offset_sectors, self.block_size
        )
    }
}
impl FromStr for Dust {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let target = Dust {
            device: p.device()?,
            offset_sectors: p.value()?,
            block_size: p.value()?,
        };
        p.end()?;
        Ok(target)
    }
}

/// Whether a [`Dust`] mapping currently fails reads that land on a block
/// marked bad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReadBehavior {
    /// Reads of a bad block fail. Set by the `enable` message.
    FailOnBadBlock,
    /// Bad blocks are ignored and reads pass through. The default, and
    /// what the `disable` message restores.
    Bypass,
}

/// Whether a [`Dust`] mapping logs each bad-block event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verbosity {
    /// Bad-block events are logged. The default.
    Verbose,
    /// Logging is suppressed. Set by the `quiet` message.
    Quiet,
}

/// [`Dust`]'s runtime status: the operating mode, which is message-driven
/// rather than set in the table.
///
/// The bad-block *count* is deliberately absent — the kernel reports it
/// only in reply to the `countbadblocks` message, not in the status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Info {
    /// The backing device.
    pub device: DevId,
    /// Whether reads of a bad block currently fail.
    pub read_behavior: ReadBehavior,
    /// Whether bad-block events are logged.
    pub verbosity: Verbosity,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let behavior = match self.read_behavior {
            ReadBehavior::FailOnBadBlock => "fail_read_on_bad_block",
            ReadBehavior::Bypass => "bypass",
        };
        let verbosity = match self.verbosity {
            Verbosity::Verbose => "verbose",
            Verbosity::Quiet => "quiet",
        };
        write!(f, "{} {behavior} {verbosity}", self.device)
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let device = p.device()?;
        let read_behavior = match p.token()? {
            "fail_read_on_bad_block" => ReadBehavior::FailOnBadBlock,
            "bypass" => ReadBehavior::Bypass,
            _ => return Err(ParseError),
        };
        let verbosity = match p.token()? {
            "verbose" => Verbosity::Verbose,
            "quiet" => Verbosity::Quiet,
            _ => return Err(ParseError),
        };
        p.end()?;
        Ok(Info {
            device,
            read_behavior,
            verbosity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    #[test]
    fn dust_renders_device_offset_and_block_size() {
        let t = Dust {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
            block_size: 512,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }

    #[test]
    fn dust_display_from_str_round_trips() {
        let original = Dust {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 64,
            block_size: 512,
        };
        assert_eq!(original.to_string().parse::<Dust>(), Ok(original));
    }

    #[test]
    fn dust_from_str_rejects_malformed_params() {
        for params in ["252:1 0", "252:1 0 512 9", "garbage 0 512", ""] {
            assert!(params.parse::<Dust>().is_err(), "should reject {params:?}");
        }
    }
}
