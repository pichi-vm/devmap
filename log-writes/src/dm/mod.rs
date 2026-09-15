// SPDX-License-Identifier: Apache-2.0

//! The `log-writes` target: mirrors a device while logging every write to
//! a separate log device, for crash-consistency testing.

use std::fmt;
use std::io;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::TargetEndpoint;
use devmap_core::{ParseError, Target as DmTarget};

/// Logs every write to `device` into `log_device`, for crash-consistency
/// testing with an external replay tool. Marking points in the log is
/// message-driven — see [`devmap_core::TargetEndpoint::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// The device whose I/O is served and mirrored.
    pub device: DevId,
    /// The device that receives the write log.
    pub log_device: DevId,
}
impl DmTarget for Target {
    const NAME: &'static str = "log-writes";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.log_device)
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let target = Target {
            device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            log_device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(target)
    }
}

/// [`Target`]'s runtime status: how much has been logged, and whether
/// logging is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Entries written to the log so far.
    pub logged_entries: u64,
    /// The highest log-device sector allocated — one below the next.
    pub highest_sector: u64,
    /// Whether logging has been turned off (via the `mark` message
    /// sequence). The kernel renders this as a trailing
    /// `logging_disabled` keyword and omits it entirely when logging is
    /// live.
    pub logging_disabled: bool,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.logged_entries, self.highest_sector)?;
        if self.logging_disabled {
            f.write_str(" logging_disabled")?;
        }
        Ok(())
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let logged_entries = fields.next().ok_or(ParseError)?.parse()?;
        let highest_sector = fields.next().ok_or(ParseError)?.parse()?;
        let logging_disabled = match fields.next() {
            Some("logging_disabled") => true,
            Some(_) => return Err(ParseError),
            None => false,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info {
            logged_entries,
            highest_sector,
            logging_disabled,
        })
    }
}

/// Messages to a live [`Target`], via
/// a backend's typed target endpoint.
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `mark <description>` — record a named point in the write log, so a
    /// replay tool can roll the origin forward to exactly here.
    fn mark(&self, description: &str) -> io::Result<()> {
        self.message(&format!("mark {description}")).map(drop)
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
    fn log_writes_renders_both_devices() {
        let t = Target {
            device: DevId::new(252, 1).unwrap(),
            log_device: DevId::new(252, 2).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 log-writes 252:1 252:2");
    }

    #[test]
    fn log_writes_display_from_str_round_trips() {
        let original = Target {
            device: DevId::new(252, 1).unwrap(),
            log_device: DevId::new(252, 2).unwrap(),
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }
}
