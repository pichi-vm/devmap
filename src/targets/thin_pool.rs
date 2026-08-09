// SPDX-License-Identifier: Apache-2.0

//! The `thin-pool` target: a pool of storage backing one or more
//! thin-provisioned volumes.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// A thin-provisioning pool backing zero or more [`crate::targets::Thin`] devices.
/// Provisioning (`create_thin`/`create_snap`/`delete`) is
/// message-driven — see [`crate::Device::message`]. Build via
/// [`ThinPool::builder`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)] // mirrors dm-thin's five kernel feature flags
pub struct ThinPool {
    metadata: DevId,
    data: DevId,
    data_block_size_sectors: u64,
    low_water_mark_blocks: u64,
    skip_block_zeroing: bool,
    ignore_discard: bool,
    no_discard_passdown: bool,
    read_only: bool,
    error_if_no_space: bool,
}
impl ThinPool {
    /// Start building a [`ThinPool`]. Feature flags default to off; set
    /// the ones you need on the returned builder, then `.build()`.
    #[must_use]
    pub fn builder(
        metadata: DevId,
        data: DevId,
        data_block_size_sectors: u64,
        low_water_mark_blocks: u64,
    ) -> Builder {
        Builder {
            metadata,
            data,
            data_block_size_sectors,
            low_water_mark_blocks,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: false,
            read_only: false,
            error_if_no_space: false,
        }
    }

    /// The metadata device.
    #[must_use]
    pub fn metadata(&self) -> DevId {
        self.metadata
    }
    /// The data device.
    #[must_use]
    pub fn data(&self) -> DevId {
        self.data
    }
    /// The data block size in sectors.
    #[must_use]
    pub fn data_block_size_sectors(&self) -> u64 {
        self.data_block_size_sectors
    }
    /// The low-water-mark, in blocks.
    #[must_use]
    pub fn low_water_mark_blocks(&self) -> u64 {
        self.low_water_mark_blocks
    }
    /// Whether newly-provisioned blocks are left unzeroed.
    #[must_use]
    pub fn skip_block_zeroing(&self) -> bool {
        self.skip_block_zeroing
    }
    /// Whether discard support is disabled.
    #[must_use]
    pub fn ignore_discard(&self) -> bool {
        self.ignore_discard
    }
    /// Whether discards are not passed down to the data device.
    #[must_use]
    pub fn no_discard_passdown(&self) -> bool {
        self.no_discard_passdown
    }
    /// Whether the pool is loaded read-only.
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    /// Whether I/O errors (rather than queues) once out of space.
    #[must_use]
    pub fn error_if_no_space(&self) -> bool {
        self.error_if_no_space
    }
}
impl Target for ThinPool {
    const NAME: &'static str = "thin-pool";
    type Table = Self;
    type Info = RawInfo;
}
impl fmt::Display for ThinPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.metadata, self.data, self.data_block_size_sectors, self.low_water_mark_blocks
        )?;
        let flags: [(bool, &str); 5] = [
            (self.skip_block_zeroing, "skip_block_zeroing"),
            (self.ignore_discard, "ignore_discard"),
            (self.no_discard_passdown, "no_discard_passdown"),
            (self.read_only, "read_only"),
            (self.error_if_no_space, "error_if_no_space"),
        ];
        let count = flags.iter().filter(|(set, _)| *set).count();
        write!(f, " {count}")?;
        for (set, name) in flags {
            if set {
                write!(f, " {name}")?;
            }
        }
        Ok(())
    }
}
impl FromStr for ThinPool {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let mut pool = ThinPool {
            metadata: p.device()?,
            data: p.device()?,
            data_block_size_sectors: p.value()?,
            low_water_mark_blocks: p.value()?,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: false,
            read_only: false,
            error_if_no_space: false,
        };
        // Every dm-thin feature is a bare flag, so the count is both a
        // token count and a feature count.
        let count: usize = p.value()?;
        for _ in 0..count {
            match p.token()? {
                "skip_block_zeroing" => pool.skip_block_zeroing = true,
                "ignore_discard" => pool.ignore_discard = true,
                "no_discard_passdown" => pool.no_discard_passdown = true,
                "read_only" => pool.read_only = true,
                "error_if_no_space" => pool.error_if_no_space = true,
                _ => return Err(ParseError),
            }
        }
        p.end()?;
        Ok(pool)
    }
}

/// Builder for [`ThinPool`] — see [`ThinPool::builder`].
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // mirrors ThinPool's five kernel feature flags
pub struct Builder {
    metadata: DevId,
    data: DevId,
    data_block_size_sectors: u64,
    low_water_mark_blocks: u64,
    skip_block_zeroing: bool,
    ignore_discard: bool,
    no_discard_passdown: bool,
    read_only: bool,
    error_if_no_space: bool,
}
impl Builder {
    /// Don't zero newly-provisioned blocks before use.
    #[must_use]
    pub fn skip_block_zeroing(mut self, on: bool) -> Self {
        self.skip_block_zeroing = on;
        self
    }
    /// Disable discard support.
    #[must_use]
    pub fn ignore_discard(mut self, on: bool) -> Self {
        self.ignore_discard = on;
        self
    }
    /// Don't pass discards down to the underlying data device.
    #[must_use]
    pub fn no_discard_passdown(mut self, on: bool) -> Self {
        self.no_discard_passdown = on;
        self
    }
    /// Load the pool read-only.
    #[must_use]
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Error (rather than queue) I/O once the pool is out of space.
    #[must_use]
    pub fn error_if_no_space(mut self, on: bool) -> Self {
        self.error_if_no_space = on;
        self
    }
    /// Finish building the [`ThinPool`].
    #[must_use]
    pub fn build(self) -> ThinPool {
        ThinPool {
            metadata: self.metadata,
            data: self.data,
            data_block_size_sectors: self.data_block_size_sectors,
            low_water_mark_blocks: self.low_water_mark_blocks,
            skip_block_zeroing: self.skip_block_zeroing,
            ignore_discard: self.ignore_discard,
            no_discard_passdown: self.no_discard_passdown,
            read_only: self.read_only,
            error_if_no_space: self.error_if_no_space,
        }
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
    fn thin_pool_renders_only_set_feature_flags() {
        let t = ThinPool::builder(
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            128,
            0,
        )
        .no_discard_passdown(true)
        .error_if_no_space(true)
        .build();
        assert_eq!(
            line(0, 1_048_576, &t),
            "0 1048576 thin-pool 252:1 252:2 128 0 2 no_discard_passdown error_if_no_space"
        );
    }

    #[test]
    fn thin_pool_display_from_str_round_trips_every_flag() {
        let base = || {
            ThinPool::builder(
                DevId::new(252, 1).unwrap(),
                DevId::new(252, 2).unwrap(),
                128,
                64,
            )
        };
        let cases = [
            base().build(),
            base().skip_block_zeroing(true).build(),
            base().ignore_discard(true).build(),
            base().no_discard_passdown(true).build(),
            base().read_only(true).build(),
            base().error_if_no_space(true).build(),
            base()
                .skip_block_zeroing(true)
                .ignore_discard(true)
                .no_discard_passdown(true)
                .read_only(true)
                .error_if_no_space(true)
                .build(),
        ];
        for original in cases {
            assert_eq!(
                original.to_string().parse::<ThinPool>().as_ref(),
                Ok(&original)
            );
        }
    }

    #[test]
    fn thin_pool_from_str_rejects_a_count_disagreeing_with_the_flags() {
        assert!("252:1 252:2 128 0 2 read_only".parse::<ThinPool>().is_err());
        assert!("252:1 252:2 128 0 0 read_only".parse::<ThinPool>().is_err());
    }

    #[test]
    fn thin_pool_from_str_rejects_an_unknown_flag() {
        assert!(
            "252:1 252:2 128 0 1 no_such_flag"
                .parse::<ThinPool>()
                .is_err()
        );
    }
}
