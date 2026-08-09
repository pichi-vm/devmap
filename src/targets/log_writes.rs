// SPDX-License-Identifier: Apache-2.0

//! The `log-writes` target: mirrors a device while logging every write to
//! a separate log device, for crash-consistency testing.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// Logs every write to `device` into `log_device`, for crash-consistency
/// testing with an external replay tool. Marking points in the log is
/// message-driven — see [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogWrites {
    /// The device whose I/O is served and mirrored.
    pub device: DevId,
    /// The device that receives the write log.
    pub log_device: DevId,
}
impl Target for LogWrites {
    const NAME: &'static str = "log-writes";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for LogWrites {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.log_device)
    }
}
impl FromStr for LogWrites {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let target = LogWrites {
            device: p.device()?,
            log_device: p.device()?,
        };
        p.end()?;
        Ok(target)
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

    #[test]
    fn log_writes_renders_both_devices() {
        let t = LogWrites {
            device: DevId::new(252, 1).unwrap(),
            log_device: DevId::new(252, 2).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 log-writes 252:1 252:2");
    }

    #[test]
    fn log_writes_display_from_str_round_trips() {
        let original = LogWrites {
            device: DevId::new(252, 1).unwrap(),
            log_device: DevId::new(252, 2).unwrap(),
        };
        assert_eq!(original.to_string().parse::<LogWrites>(), Ok(original));
    }
}
