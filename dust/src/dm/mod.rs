// SPDX-License-Identifier: Apache-2.0

//! The `dust` target: injects read/write errors at chosen blocks for
//! fault-injection testing.

use std::fmt;
use std::io;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::TargetEndpoint;
use devmap_core::{ParseError, Target as DmTarget};

/// Injects read/write errors at specific blocks, for fault-injection
/// testing. Bad-block management is message-driven — see
/// [`devmap_core::TargetEndpoint::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The backing device.
    pub device: DevId,
    /// The starting offset in sectors.
    pub offset_sectors: u64,
    /// The block size in bytes.
    pub block_size: u32,
}
impl DmTarget for Target {
    const NAME: &'static str = "dust";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.device, self.offset_sectors, self.block_size
        )
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let target = Target {
            device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            offset_sectors: fields.next().ok_or(ParseError)?.parse()?,
            block_size: fields.next().ok_or(ParseError)?.parse()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(target)
    }
}

/// Whether a [`Target`] mapping currently fails reads that land on a block
/// marked bad.
///
/// Encoded as `fail_read_on_bad_block` or `bypass`; other tokens are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReadBehavior {
    /// Reads of a bad block fail. Set by the `enable` message.
    FailOnBadBlock,
    /// Bad blocks are ignored and reads pass through. The default, and
    /// what the `disable` message restores.
    Bypass,
}

impl FromStr for ReadBehavior {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fail_read_on_bad_block" => Ok(Self::FailOnBadBlock),
            "bypass" => Ok(Self::Bypass),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for ReadBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::FailOnBadBlock => "fail_read_on_bad_block",
            Self::Bypass => "bypass",
        })
    }
}

/// Whether a [`Target`] mapping logs each bad-block event.
///
/// Encoded as `verbose` or `quiet`; other tokens are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verbosity {
    /// Bad-block events are logged. The default.
    Verbose,
    /// Logging is suppressed. Set by the `quiet` message.
    Quiet,
}

impl FromStr for Verbosity {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verbose" => Ok(Self::Verbose),
            "quiet" => Ok(Self::Quiet),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for Verbosity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Verbose => "verbose",
            Self::Quiet => "quiet",
        })
    }
}

/// [`Target`]'s runtime status: the operating mode, which is message-driven
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
        write!(
            f,
            "{} {} {}",
            self.device, self.read_behavior, self.verbosity
        )
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let device = fields.next().ok_or(ParseError)?.parse::<DevId>()?;
        let read_behavior = fields.next().ok_or(ParseError)?.parse()?;
        let verbosity = fields.next().ok_or(ParseError)?.parse()?;
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info {
            device,
            read_behavior,
            verbosity,
        })
    }
}

/// Messages to a live [`Target`], via
/// a backend's typed target endpoint. Bad-block injection is
/// entirely message-driven.
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `addbadblock <block>` — mark a block bad.
    fn add_bad_block(&self, block: u64) -> io::Result<()> {
        self.message(&format!("addbadblock {block}")).map(drop)
    }

    /// `removebadblock <block>` — unmark a block.
    fn remove_bad_block(&self, block: u64) -> io::Result<()> {
        self.message(&format!("removebadblock {block}")).map(drop)
    }

    /// `clearbadblocks` — clear the entire bad-block list.
    fn clear_bad_blocks(&self) -> io::Result<()> {
        self.message("clearbadblocks").map(drop)
    }

    /// `countbadblocks` — how many blocks are currently marked bad.
    ///
    /// # Errors
    ///
    /// The kernel's `io::Error`, or an error if the reply can't be parsed.
    fn count_bad_blocks(&self) -> io::Result<u64> {
        // The kernel replies "countbadblocks: <n> badblock(s) found".
        let reply = self
            .message("countbadblocks")?
            .ok_or_else(|| io::Error::other("countbadblocks: no reply"))?;
        reply
            .split_whitespace()
            .nth(1)
            .and_then(|tok| tok.parse().ok())
            .ok_or_else(|| io::Error::other(format!("countbadblocks: unexpected reply {reply:?}")))
    }

    /// `enable` — start failing reads that land on a bad block.
    fn enable(&self) -> io::Result<()> {
        self.message("enable").map(drop)
    }

    /// `disable` — bypass bad blocks so reads pass through.
    fn disable(&self) -> io::Result<()> {
        self.message("disable").map(drop)
    }

    /// `quiet` — toggle suppression of per-event logging.
    fn quiet(&self) -> io::Result<()> {
        self.message("quiet").map(drop)
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
    fn dust_renders_device_offset_and_block_size() {
        let t = Target {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
            block_size: 512,
        };
        assert_eq!(line(0, 8192, &t), "0 8192 dust 252:1 0 512");
    }

    #[test]
    fn dust_display_from_str_round_trips() {
        let original = Target {
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 64,
            block_size: 512,
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }

    #[test]
    fn dust_from_str_rejects_malformed_params() {
        for params in ["252:1 0", "252:1 0 512 9", "garbage 0 512", ""] {
            assert!(
                params.parse::<Target>().is_err(),
                "should reject {params:?}"
            );
        }
    }
}
