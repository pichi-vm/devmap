// SPDX-License-Identifier: Apache-2.0

//! The `striped` target: spreads I/O across several devices in fixed-size
//! chunks (RAID0-style striping).

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, Target};

/// Concatenates several devices into one striped range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Striped {
    /// The chunk size in sectors.
    pub chunk_size_sectors: u32,
    /// The `(device, offset)` stripe pairs.
    pub stripes: Vec<(DevId, u64)>,
}
impl Target for Striped {
    const NAME: &'static str = "striped";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Striped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.stripes.len(), self.chunk_size_sectors)?;
        for (device, offset) in &self.stripes {
            write!(f, " {device} {offset}")?;
        }
        Ok(())
    }
}
impl FromStr for Striped {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let count: usize = p.value()?;
        let chunk_size_sectors = p.value()?;
        // Grown rather than reserved: `count` comes off the wire, so a
        // malformed row must not turn into a huge allocation. Running out
        // of tokens fails the pair read instead.
        let mut stripes = Vec::new();
        for _ in 0..count {
            stripes.push((p.device()?, p.value()?));
        }
        p.end()?;
        Ok(Striped {
            chunk_size_sectors,
            stripes,
        })
    }
}

/// Whether one stripe of a [`Striped`] mapping is taking I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StripeHealth {
    /// No errors recorded on this stripe (the kernel's `A`).
    Alive,
    /// This stripe has recorded at least one I/O error (`D`). The count
    /// is not exposed in the status line, only that it is non-zero.
    Dead,
}

/// [`Striped`]'s runtime status: each stripe's device and whether it has
/// taken errors.
///
/// Device and health arrive in the kernel's line as two separate runs —
/// the devices, then a run of health characters — but both are in stripe
/// order, so this pairs them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Info {
    /// One entry per stripe, in stripe order.
    pub stripes: Vec<(DevId, StripeHealth)>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.stripes.len())?;
        for (device, _) in &self.stripes {
            write!(f, " {device}")?;
        }
        // The literal 1 is dm's "one status argument follows" count; the
        // health run is that single argument.
        f.write_str(" 1 ")?;
        for (_, health) in &self.stripes {
            f.write_str(match health {
                StripeHealth::Alive => "A",
                StripeHealth::Dead => "D",
            })?;
        }
        Ok(())
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let count: usize = p.value()?;
        // Grown rather than reserved: `count` comes off the wire.
        let mut devices = Vec::new();
        for _ in 0..count {
            devices.push(p.device()?);
        }
        if p.value::<u32>()? != 1 {
            return Err(ParseError);
        }
        // One health character per stripe, concatenated into a single
        // token, so its length must match the count read above.
        let health = p.token()?;
        if health.len() != count {
            return Err(ParseError);
        }
        let stripes = devices
            .into_iter()
            .zip(health.chars())
            .map(|(device, c)| {
                let health = match c {
                    'A' => StripeHealth::Alive,
                    'D' => StripeHealth::Dead,
                    _ => return Err(ParseError),
                };
                Ok((device, health))
            })
            .collect::<Result<Vec<_>, ParseError>>()?;
        p.end()?;
        Ok(Info { stripes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    #[test]
    fn striped_renders_stripe_count_and_pairs() {
        let t = Striped {
            chunk_size_sectors: 128,
            stripes: vec![
                (DevId::new(252, 1).unwrap(), 0),
                (DevId::new(252, 2).unwrap(), 0),
            ],
        };
        assert_eq!(line(0, 2048, &t), "0 2048 striped 2 128 252:1 0 252:2 0");
    }

    #[test]
    fn striped_display_from_str_round_trips() {
        let original = Striped {
            chunk_size_sectors: 128,
            stripes: vec![
                (DevId::new(252, 1).unwrap(), 0),
                (DevId::new(252, 2).unwrap(), 64),
            ],
        };
        assert_eq!(original.to_string().parse::<Striped>(), Ok(original));
    }

    #[test]
    fn striped_from_str_rejects_a_count_disagreeing_with_the_pairs() {
        assert!("3 128 252:1 0 252:2 0".parse::<Striped>().is_err());
        assert!("1 128 252:1 0 252:2 0".parse::<Striped>().is_err());
    }
}
