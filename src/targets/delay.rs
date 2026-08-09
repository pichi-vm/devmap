// SPDX-License-Identifier: Apache-2.0

//! The `delay` target: routes I/O to an underlying device after a
//! configurable delay, optionally using separate legs per I/O class.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// One `<device, offset, delay>` leg of a [`Delay`] mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Leg {
    /// The device I/O is routed to.
    pub device: DevId,
    /// Starting offset into `device`, in 512-byte sectors.
    pub offset_sectors: u64,
    /// Delay applied to each I/O on this leg, in milliseconds.
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
pub struct Delay {
    /// Leg applied to read I/O; also the fallback for any unset leg.
    pub read: Leg,
    /// Leg applied to write I/O; falls back to `read` if `None`.
    pub write: Option<Leg>,
    /// Leg applied to flush I/O; falls back to `read` if `None`.
    pub flush: Option<Leg>,
}
impl Target for Delay {
    const NAME: &'static str = "delay";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for Delay {
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
impl FromStr for Delay {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        fn leg(p: &mut Params<'_>) -> Result<Leg, ParseError> {
            Ok(Leg {
                device: p.device()?,
                offset_sectors: p.value()?,
                delay_ms: p.value()?,
            })
        }

        let mut p = Params::new(s);
        let tokens = p.remaining();
        let read = leg(&mut p)?;
        let (write, flush) = match tokens {
            3 => (None, None),
            // The kernel's 6-argument form binds flush to the write leg.
            // `Display` never emits it — it widens to 9 — but a device
            // configured elsewhere can, so record the implied flush leg
            // explicitly rather than losing it to the `read` fallback.
            6 => {
                let w = leg(&mut p)?;
                (Some(w), Some(w))
            }
            9 => (Some(leg(&mut p)?), Some(leg(&mut p)?)),
            _ => return Err(ParseError),
        };
        p.end()?;
        Ok(Delay { read, write, flush })
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
    fn delay_renders_three_arg_form_when_only_read_is_set() {
        let t = Delay {
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
        let t = Delay {
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
        let t = Delay {
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
        let t = Delay {
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
            let original = Delay { read, write, flush };
            assert_eq!(original.to_string().parse::<Delay>(), Ok(original));
        }
    }

    #[test]
    fn delay_from_str_reads_the_kernel_six_argument_form() {
        let parsed: Delay = "252:1 0 500 252:2 0 100".parse().expect("six-arg form");
        let write = Leg::new(DevId::new(252, 2).unwrap(), 0, 100);
        assert_eq!(parsed.write, Some(write));
        assert_eq!(parsed.flush, Some(write));
    }

    #[test]
    fn delay_from_str_rejects_other_token_counts() {
        for params in ["252:1 0", "252:1 0 500 252:2", ""] {
            assert!(params.parse::<Delay>().is_err(), "should reject {params:?}");
        }
    }
}
