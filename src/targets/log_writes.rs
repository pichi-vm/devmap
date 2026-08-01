// SPDX-License-Identifier: Apache-2.0

//! The `log-writes` target: mirrors a device while logging every write to
//! a separate log device, for crash-consistency testing.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

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
    const TYPE_NAME: &'static str = "log-writes";
    type Info = RawInfo;
}
impl fmt::Display for LogWrites {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.device, self.log_device)
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
    fn log_writes_renders_both_devices() {
        let t = LogWrites {
            device: DevId::new(252, 1).unwrap(),
            log_device: DevId::new(252, 2).unwrap(),
        };
        assert_eq!(line(0, 8192, &t), "0 8192 log-writes 252:1 252:2");
    }
}
