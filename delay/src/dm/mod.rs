// SPDX-License-Identifier: Apache-2.0

//! The `delay` target: routes I/O to an underlying device after a
//! configurable delay, optionally using separate legs per I/O class.

use std::fmt;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::{ParseError, Target as DmTarget};

/// One `<device, offset, delay>` leg of a [`Target`] mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Leg {
    /// The device I/O is routed to.
    pub device: DevId,
    /// Starting offset into `device`, in 512-byte sectors.
    pub offset_sectors: u64,
    /// Target applied to each I/O on this leg, in milliseconds.
    pub delay_ms: u32,
}

impl Leg {
    /// A delay leg: route I/O to `device` at `offset_sectors`, delayed
    /// by `delay_ms` milliseconds.
    #[must_use]
    pub fn new(device: DevId, offset_sectors: u64, delay_ms: u32) -> Self {
        Self {
            device,
            offset_sectors,
            delay_ms,
        }
    }
}

/// Delays I/O to an underlying device, optionally applying a different
/// leg to reads, writes, and flushes.
///
/// Only `read` is mandatory; any unset leg (`write`/`flush`) follows the
/// `read` leg's device, offset, and delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// Leg applied to read I/O; also the fallback for any unset leg.
    pub read: Leg,
    /// Leg applied to write I/O; falls back to `read` if `None`.
    pub write: Option<Leg>,
    /// Leg applied to flush I/O; falls back to `read` if `None`.
    pub flush: Option<Leg>,
}
impl DmTarget for Target {
    const NAME: &'static str = "delay";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let read = self.read;
        write!(
            f,
            "{} {} {}",
            read.device, read.offset_sectors, read.delay_ms
        )?;
        // Once any second leg exists, emit both write and flush explicitly
        // (9-arg form): the kernel's 6-arg form would bind flush to the
        // write leg, which would silently contradict "unset legs follow
        // read". Each unset leg falls back to `read`.
        if self.write.is_some() || self.flush.is_some() {
            let w = self.write.unwrap_or(read);
            write!(f, " {} {} {}", w.device, w.offset_sectors, w.delay_ms)?;
            let fl = self.flush.unwrap_or(read);
            write!(f, " {} {} {}", fl.device, fl.offset_sectors, fl.delay_ms)?;
        }
        Ok(())
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn leg(fields: &mut std::str::SplitWhitespace<'_>) -> Result<Leg, ParseError> {
            Ok(Leg {
                device: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
                offset_sectors: fields.next().ok_or(ParseError)?.parse()?,
                delay_ms: fields.next().ok_or(ParseError)?.parse()?,
            })
        }

        let mut fields = s.split_whitespace();
        let tokens = fields.clone().count();
        let read = leg(&mut fields)?;
        let (write, flush) = match tokens {
            3 => (None, None),
            // The kernel's 6-argument form binds flush to the write leg.
            // `Display` never emits it — it widens to 9 — but a device
            // configured elsewhere can, so record the implied flush leg
            // explicitly rather than losing it to the `read` fallback.
            6 => {
                let w = leg(&mut fields)?;
                (Some(w), Some(w))
            }
            9 => (Some(leg(&mut fields)?), Some(leg(&mut fields)?)),
            _ => return Err(ParseError),
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Target { read, write, flush })
    }
}

/// [`Target`]'s runtime status: the I/O it has delayed so far, counted per
/// direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Reads delayed.
    pub read_ops: u32,
    /// Writes delayed.
    pub write_ops: u32,
    /// Flushes delayed.
    pub flush_ops: u32,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.read_ops, self.write_ops, self.flush_ops)
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let info = Info {
            read_ops: fields.next().ok_or(ParseError)?.parse()?,
            write_ops: fields.next().ok_or(ParseError)?.parse()?,
            flush_ops: fields.next().ok_or(ParseError)?.parse()?,
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(info)
    }
}

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
    fn delay_renders_three_arg_form_when_only_read_is_set() {
        let t = Target {
            read: Leg::new(DevId::new(252, 1).unwrap(), 0, 500),
            write: None,
            flush: None,
        };
        assert_eq!(line(0, 8, &t), "0 8 delay 252:1 0 500");
    }

    #[test]
    fn delay_renders_nine_arg_form_when_write_is_set_flush_defaults_to_read() {
        // write set, flush unset -> 9-arg form with flush = read (not the
        // kernel's 6-arg "flush follows write").
        let t = Target {
            read: Leg::new(DevId::new(252, 1).unwrap(), 0, 500),
            write: Some(Leg::new(DevId::new(252, 2).unwrap(), 0, 100)),
            flush: None,
        };
        assert_eq!(
            line(0, 8, &t),
            "0 8 delay 252:1 0 500 252:2 0 100 252:1 0 500"
        );
    }

    #[test]
    fn delay_renders_nine_arg_form_when_flush_is_set() {
        let t = Target {
            read: Leg::new(DevId::new(252, 1).unwrap(), 0, 500),
            write: Some(Leg::new(DevId::new(252, 2).unwrap(), 0, 100)),
            flush: Some(Leg::new(DevId::new(252, 3).unwrap(), 0, 50)),
        };
        assert_eq!(
            line(0, 8, &t),
            "0 8 delay 252:1 0 500 252:2 0 100 252:3 0 50"
        );
    }

    #[test]
    fn delay_flush_without_explicit_write_falls_back_to_read_leg() {
        let t = Target {
            read: Leg::new(DevId::new(252, 1).unwrap(), 0, 500),
            write: None,
            flush: Some(Leg::new(DevId::new(252, 3).unwrap(), 0, 50)),
        };
        assert_eq!(
            line(0, 8, &t),
            "0 8 delay 252:1 0 500 252:1 0 500 252:3 0 50"
        );
    }

    #[test]
    fn delay_display_from_str_round_trips() {
        let read = Leg::new(DevId::new(252, 1).unwrap(), 0, 500);
        for (write, flush) in [
            (None, None),
            (
                Some(Leg::new(DevId::new(252, 2).unwrap(), 0, 100)),
                Some(Leg::new(DevId::new(252, 3).unwrap(), 0, 50)),
            ),
        ] {
            let original = Target { read, write, flush };
            assert_eq!(original.to_string().parse::<Target>(), Ok(original));
        }
    }

    #[test]
    fn delay_from_str_reads_the_kernel_six_argument_form() {
        let parsed: Target = "252:1 0 500 252:2 0 100".parse().expect("six-arg form");
        let write = Leg::new(DevId::new(252, 2).unwrap(), 0, 100);
        assert_eq!(parsed.write, Some(write));
        assert_eq!(parsed.flush, Some(write));
    }

    #[test]
    fn delay_from_str_rejects_other_token_counts() {
        for params in ["252:1 0", "252:1 0 500 252:2", ""] {
            assert!(
                params.parse::<Target>().is_err(),
                "should reject {params:?}"
            );
        }
    }
}
