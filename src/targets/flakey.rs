// SPDX-License-Identifier: Apache-2.0

//! The `flakey` target: makes an otherwise normal device intermittently
//! fail or silently corrupt I/O, for fault-injection testing.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// Which I/O direction a [`Feature::CorruptBioByte`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// Corrupt matching read I/O.
    Read,
    /// Corrupt matching write I/O.
    Write,
}

/// One feature flag of a [`Flakey`] mapping. A closed set: the kernel
/// target supports exactly these six, no more.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// Fail all reads during the down interval.
    ErrorReads,
    /// Silently discard writes during the down interval.
    DropWrites,
    /// Fail all writes during the down interval.
    ErrorWrites,
    /// Overwrite one byte of matching bios during the down interval.
    /// `nth_byte` is 1-based (the kernel rejects 0).
    CorruptBioByte {
        /// 1-based index of the byte to overwrite within each bio.
        nth_byte: u32,
        /// Whether reads or writes are corrupted.
        direction: Direction,
        /// The byte value written in place of the original.
        value: u8,
        /// Bio-opcode flags restricting which bios are affected (`0` for
        /// all).
        flags: u32,
    },
    /// Randomly corrupt a byte in read bios. `probability` is the chance
    /// per bio in the kernel range `0..=1_000_000_000` (1e9 = 100%).
    RandomReadCorrupt {
        /// Per-bio corruption chance in `0..=1_000_000_000` (1e9 = 100%).
        probability: u32,
    },
    /// Randomly corrupt a byte in write bios. `probability` is the chance
    /// per bio in the kernel range `0..=1_000_000_000` (1e9 = 100%).
    RandomWriteCorrupt {
        /// Per-bio corruption chance in `0..=1_000_000_000` (1e9 = 100%).
        probability: u32,
    },
}

// Raw *argument-token* count a `Feature` contributes to the table line's
// `<#num_features>` field: the count is of tokens, not feature groups, so
// a bare flag is 1 token, `corrupt_bio_byte` is 5 (itself plus 4 args),
// and the `random_*_corrupt` features are 2 (themselves plus 1 arg each).
fn flakey_feature_token_count(feature: &Feature) -> u32 {
    match feature {
        Feature::ErrorReads | Feature::DropWrites | Feature::ErrorWrites => 1,
        Feature::CorruptBioByte { .. } => 5,
        Feature::RandomReadCorrupt { .. } | Feature::RandomWriteCorrupt { .. } => 2,
    }
}

/// Write one [`Feature`] token group, leading space included.
fn write_flakey_feature<W: fmt::Write + ?Sized>(w: &mut W, feature: &Feature) -> fmt::Result {
    match feature {
        Feature::ErrorReads => w.write_str(" error_reads"),
        Feature::DropWrites => w.write_str(" drop_writes"),
        Feature::ErrorWrites => w.write_str(" error_writes"),
        Feature::CorruptBioByte {
            nth_byte,
            direction,
            value,
            flags,
        } => {
            let direction = match direction {
                Direction::Read => 'r',
                Direction::Write => 'w',
            };
            write!(
                w,
                " corrupt_bio_byte {nth_byte} {direction} {value} {flags}"
            )
        }
        Feature::RandomReadCorrupt { probability } => {
            write!(w, " random_read_corrupt {probability}")
        }
        Feature::RandomWriteCorrupt { probability } => {
            write!(w, " random_write_corrupt {probability}")
        }
    }
}

/// Injects configurable faults (I/O errors, silent data corruption)
/// into a normally-behaving device, for fault-injection testing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Flakey {
    device: DevId,
    offset_sectors: u64,
    up_interval_secs: u32,
    down_interval_secs: u32,
    features: Vec<Feature>,
}
impl Flakey {
    /// Construct a [`Flakey`].
    ///
    /// The kernel validates the interval, feature counts, and feature
    /// combinations on table load, rejecting bad values with `EINVAL`.
    #[must_use]
    pub fn new(
        device: DevId,
        offset_sectors: u64,
        up_interval_secs: u32,
        down_interval_secs: u32,
        features: Vec<Feature>,
    ) -> Self {
        Flakey {
            device,
            offset_sectors,
            up_interval_secs,
            down_interval_secs,
            features,
        }
    }

    /// The backing device.
    #[must_use]
    pub fn device(&self) -> DevId {
        self.device
    }
    /// The starting offset in sectors.
    #[must_use]
    pub fn offset_sectors(&self) -> u64 {
        self.offset_sectors
    }
    /// The up-interval in seconds.
    #[must_use]
    pub fn up_interval_secs(&self) -> u32 {
        self.up_interval_secs
    }
    /// The down-interval in seconds.
    #[must_use]
    pub fn down_interval_secs(&self) -> u32 {
        self.down_interval_secs
    }
    /// The configured features.
    #[must_use]
    pub fn features(&self) -> &[Feature] {
        &self.features
    }
}
impl Target for Flakey {
    const NAME: &'static str = "flakey";
    type Info = RawInfo;
}
impl fmt::Display for Flakey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.device, self.offset_sectors, self.up_interval_secs, self.down_interval_secs
        )?;
        let token_count: u32 = self.features.iter().map(flakey_feature_token_count).sum();
        write!(f, " {token_count}")?;
        for feature in &self.features {
            write_flakey_feature(f, feature)?;
        }
        Ok(())
    }
}
impl FromStr for Flakey {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let device = p.device()?;
        let offset_sectors = p.value()?;
        let up_interval_secs = p.value()?;
        let down_interval_secs = p.value()?;

        // Counted in tokens, not features, so the loop tracks how many
        // tokens each feature consumed rather than iterating `count`
        // times. A count landing mid-feature leaves `consumed > count`.
        let count: u32 = p.value()?;
        let mut features = Vec::new();
        let mut consumed = 0;
        while consumed < count {
            let feature = match p.token()? {
                "error_reads" => Feature::ErrorReads,
                "drop_writes" => Feature::DropWrites,
                "error_writes" => Feature::ErrorWrites,
                "corrupt_bio_byte" => {
                    let nth_byte = p.value()?;
                    let direction = match p.token()? {
                        "r" => Direction::Read,
                        "w" => Direction::Write,
                        _ => return Err(ParseError),
                    };
                    Feature::CorruptBioByte {
                        nth_byte,
                        direction,
                        value: p.value()?,
                        flags: p.value()?,
                    }
                }
                "random_read_corrupt" => Feature::RandomReadCorrupt {
                    probability: p.value()?,
                },
                "random_write_corrupt" => Feature::RandomWriteCorrupt {
                    probability: p.value()?,
                },
                _ => return Err(ParseError),
            };
            consumed += flakey_feature_token_count(&feature);
            features.push(feature);
        }
        if consumed != count {
            return Err(ParseError);
        }
        p.end()?;

        Ok(Flakey {
            device,
            offset_sectors,
            up_interval_secs,
            down_interval_secs,
            features,
        })
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
    fn flakey_renders_zero_features_when_none_given() {
        let t = Flakey::new(DevId::new(252, 1).unwrap(), 0, 60, 5, vec![]);
        assert_eq!(line(0, 8192, &t), "0 8192 flakey 252:1 0 60 5 0");
    }

    #[test]
    fn flakey_renders_feature_token_counts_not_feature_counts() {
        let t = Flakey::new(
            DevId::new(252, 1).unwrap(),
            0,
            60,
            5,
            vec![
                Feature::ErrorReads,
                Feature::CorruptBioByte {
                    nth_byte: 32,
                    direction: Direction::Write,
                    value: 1,
                    flags: 0,
                },
                Feature::RandomWriteCorrupt { probability: 10 },
            ],
        );
        // token count: error_reads(1) + corrupt_bio_byte(5) + random_write_corrupt(2) = 8
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 flakey 252:1 0 60 5 8 error_reads corrupt_bio_byte 32 w 1 0 random_write_corrupt 10"
        );
    }

    #[test]
    fn flakey_renders_drop_writes_token() {
        let t = Flakey::new(
            DevId::new(252, 1).unwrap(),
            0,
            60,
            5,
            vec![Feature::DropWrites],
        );
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 flakey 252:1 0 60 5 1 drop_writes"
        );
    }

    #[test]
    fn flakey_renders_error_writes_token() {
        let t = Flakey::new(
            DevId::new(252, 1).unwrap(),
            0,
            60,
            5,
            vec![Feature::ErrorWrites],
        );
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 flakey 252:1 0 60 5 1 error_writes"
        );
    }

    #[test]
    fn flakey_renders_random_read_corrupt_token() {
        let t = Flakey::new(
            DevId::new(252, 1).unwrap(),
            0,
            60,
            5,
            vec![Feature::RandomReadCorrupt {
                probability: 500_000_000,
            }],
        );
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 flakey 252:1 0 60 5 2 random_read_corrupt 500000000"
        );
    }

    #[test]
    fn flakey_renders_read_direction_token() {
        let t = Flakey::new(
            DevId::new(252, 1).unwrap(),
            0,
            60,
            5,
            vec![Feature::CorruptBioByte {
                nth_byte: 1,
                direction: Direction::Read,
                value: 7,
                flags: 0,
            }],
        );
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 flakey 252:1 0 60 5 5 corrupt_bio_byte 1 r 7 0"
        );
    }

    #[test]
    fn flakey_display_from_str_round_trips_every_feature() {
        let features = [
            vec![],
            vec![Feature::ErrorReads],
            vec![Feature::DropWrites],
            vec![Feature::ErrorWrites],
            vec![Feature::RandomReadCorrupt {
                probability: 500_000_000,
            }],
            vec![Feature::RandomWriteCorrupt { probability: 10 }],
            vec![Feature::CorruptBioByte {
                nth_byte: 32,
                direction: Direction::Write,
                value: 1,
                flags: 0,
            }],
            vec![
                Feature::ErrorReads,
                Feature::CorruptBioByte {
                    nth_byte: 1,
                    direction: Direction::Read,
                    value: 7,
                    flags: 3,
                },
                Feature::RandomWriteCorrupt { probability: 10 },
            ],
        ];
        for features in features {
            let original = Flakey::new(DevId::new(252, 1).unwrap(), 8, 60, 5, features);
            assert_eq!(
                original.to_string().parse::<Flakey>().as_ref(),
                Ok(&original)
            );
        }
    }

    #[test]
    fn flakey_parses_the_kernels_default_feature_substitution() {
        // A table loaded with zero features reads back as an explicit
        // `error_reads error_writes` pair — the kernel names its default
        // rather than echoing what was written. The row is still exactly
        // representable, so it parses; it just isn't the value that was
        // written.
        let written = Flakey::new(DevId::new(7, 0).unwrap(), 0, 60, 5, vec![]);
        assert_eq!(written.to_string(), "7:0 0 60 5 0");
        let read: Flakey = "7:0 0 60 5 2 error_reads error_writes".parse().unwrap();
        assert_eq!(read.features(), [Feature::ErrorReads, Feature::ErrorWrites]);
        assert_ne!(read, written);
    }

    #[test]
    fn flakey_from_str_rejects_a_count_landing_mid_feature() {
        // `corrupt_bio_byte` is five tokens; a count of 3 would slice it.
        assert!(
            "252:1 0 60 5 3 corrupt_bio_byte 1 r 7 0"
                .parse::<Flakey>()
                .is_err()
        );
        assert!("252:1 0 60 5 2 error_reads".parse::<Flakey>().is_err());
    }

    #[test]
    fn flakey_from_str_rejects_unknown_features_and_directions() {
        assert!("252:1 0 60 5 1 no_such_feature".parse::<Flakey>().is_err());
        assert!(
            "252:1 0 60 5 5 corrupt_bio_byte 1 x 7 0"
                .parse::<Flakey>()
                .is_err()
        );
    }
}
