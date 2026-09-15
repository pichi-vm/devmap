// SPDX-License-Identifier: Apache-2.0

//! The `striped` target: spreads I/O across several devices in fixed-size
//! chunks (RAID0-style striping).

use std::fmt;
use std::str::FromStr;

use devmap_core::DevId;
use devmap_core::{ParseError, Target as DmTarget};

/// Concatenates several devices into one striped range.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// The chunk size in sectors.
    pub chunk_size_sectors: u32,
    /// The `(device, offset)` stripe pairs.
    pub stripes: Vec<(DevId, u64)>,
}
impl DmTarget for Target {
    const NAME: &'static str = "striped";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.stripes.len(), self.chunk_size_sectors)?;
        for (device, offset) in &self.stripes {
            write!(f, " {device} {offset}")?;
        }
        Ok(())
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let count: usize = fields.next().ok_or(ParseError)?.parse()?;
        let chunk_size_sectors = fields.next().ok_or(ParseError)?.parse()?;
        // Grown rather than reserved: `count` comes off the wire, so a
        // malformed row must not turn into a huge allocation. Running out
        // of tokens fails the pair read instead.
        let mut stripes = Vec::new();
        for _ in 0..count {
            stripes.push((
                fields.next().ok_or(ParseError)?.parse::<DevId>()?,
                fields.next().ok_or(ParseError)?.parse()?,
            ));
        }
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Target {
            chunk_size_sectors,
            stripes,
        })
    }
}

/// Whether one stripe of a [`Target`] mapping is taking I/O errors.
///
/// Encoded as `A` or `D`; parsing rejects other characters and longer strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StripeHealth {
    /// No errors recorded on this stripe (the kernel's `A`).
    Alive,
    /// This stripe has recorded at least one I/O error (`D`). The count
    /// is not exposed in the status line, only that it is non-zero.
    Dead,
}

impl TryFrom<char> for StripeHealth {
    type Error = ParseError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        match c {
            'A' => Ok(Self::Alive),
            'D' => Ok(Self::Dead),
            _ => Err(ParseError),
        }
    }
}

impl FromStr for StripeHealth {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut chars = s.chars();
        let health = Self::try_from(chars.next().ok_or(ParseError)?)?;
        if chars.next().is_some() {
            return Err(ParseError);
        }
        Ok(health)
    }
}

impl fmt::Display for StripeHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Alive => "A",
            Self::Dead => "D",
        })
    }
}

/// [`Target`]'s runtime status: each stripe's device and whether it has
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
            write!(f, "{health}")?;
        }
        Ok(())
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let count: usize = fields.next().ok_or(ParseError)?.parse()?;
        // Grown rather than reserved: `count` comes off the wire.
        let mut devices = Vec::new();
        for _ in 0..count {
            devices.push(fields.next().ok_or(ParseError)?.parse::<DevId>()?);
        }
        if fields.next().ok_or(ParseError)?.parse::<u32>()? != 1 {
            return Err(ParseError);
        }
        // One health character per stripe, concatenated into a single
        // token, so its length must match the count read above.
        let health = fields.next().ok_or(ParseError)?;
        if health.len() != count {
            return Err(ParseError);
        }
        let stripes = devices
            .into_iter()
            .zip(health.chars())
            .map(|(device, c)| Ok((device, StripeHealth::try_from(c)?)))
            .collect::<Result<Vec<_>, ParseError>>()?;
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info { stripes })
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
    fn striped_renders_stripe_count_and_pairs() {
        let t = Target {
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
        let original = Target {
            chunk_size_sectors: 128,
            stripes: vec![
                (DevId::new(252, 1).unwrap(), 0),
                (DevId::new(252, 2).unwrap(), 64),
            ],
        };
        assert_eq!(original.to_string().parse::<Target>(), Ok(original));
    }

    #[test]
    fn striped_from_str_rejects_a_count_disagreeing_with_the_pairs() {
        assert!("3 128 252:1 0 252:2 0".parse::<Target>().is_err());
        assert!("1 128 252:1 0 252:2 0".parse::<Target>().is_err());
    }
}
