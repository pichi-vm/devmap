// SPDX-License-Identifier: Apache-2.0

//! The `thin-pool` target: a pool of storage backing one or more
//! thin-provisioned volumes.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

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
    const TYPE_NAME: &'static str = "thin-pool";
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

/// Builder for [`ThinPool`] — see [`ThinPool::builder`]. At most four
/// feature flags may be set at once (the kernel rejects all five);
/// [`build`](Builder::build) enforces this.
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
    ///
    /// # Errors
    ///
    /// [`crate::Error::Usage`] if all five feature flags are set
    /// (dm-thin's `parse_pool_features` caps the count at 4 and rejects
    /// 5 with `EINVAL` before inspecting the keywords), or if
    /// `data_block_size_sectors` is outside `128..=2_097_152` or not a
    /// multiple of `128`.
    pub fn build(self) -> Result<ThinPool, crate::Error> {
        let set = u32::from(self.skip_block_zeroing)
            + u32::from(self.ignore_discard)
            + u32::from(self.no_discard_passdown)
            + u32::from(self.read_only)
            + u32::from(self.error_if_no_space);
        if set > 4 {
            return Err(crate::Error::Usage(
                "thin-pool accepts at most 4 feature flags; the kernel rejects all 5 at once".into(),
            ));
        }
        if !(128..=2_097_152).contains(&self.data_block_size_sectors)
            || !self.data_block_size_sectors.is_multiple_of(128)
        {
            return Err(crate::Error::Usage(format!(
                "thin-pool data_block_size must be in 128..=2097152 and a multiple of 128, got {}",
                self.data_block_size_sectors
            )));
        }
        Ok(ThinPool {
            metadata: self.metadata,
            data: self.data,
            data_block_size_sectors: self.data_block_size_sectors,
            low_water_mark_blocks: self.low_water_mark_blocks,
            skip_block_zeroing: self.skip_block_zeroing,
            ignore_discard: self.ignore_discard,
            no_discard_passdown: self.no_discard_passdown,
            read_only: self.read_only,
            error_if_no_space: self.error_if_no_space,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn thin_pool_renders_only_set_feature_flags() {
        let t = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 128, 0)
            .no_discard_passdown(true)
            .error_if_no_space(true)
            .build()
            .expect("valid thin-pool");
        assert_eq!(
            line(0, 1_048_576, &t),
            "0 1048576 thin-pool 252:1 252:2 128 0 2 no_discard_passdown error_if_no_space"
        );
    }

    #[test]
    fn thin_pool_with_all_five_feature_flags_is_rejected_at_build() {
        let r = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 128, 0)
            .skip_block_zeroing(true)
            .ignore_discard(true)
            .no_discard_passdown(true)
            .read_only(true)
            .error_if_no_space(true)
            .build();
        assert!(matches!(r, Err(Error::Usage(_))));
    }

    #[test]
    fn thin_pool_with_four_feature_flags_builds() {
        let r = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 128, 0)
            .skip_block_zeroing(true)
            .ignore_discard(true)
            .no_discard_passdown(true)
            .read_only(true)
            .build();
        assert!(r.is_ok());
    }

    #[test]
    fn thin_pool_bad_data_block_size_is_rejected() {
        // Too small.
        let small = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 64, 0).build();
        assert!(matches!(small, Err(Error::Usage(_))));
        // Too large.
        let large = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 2_097_280, 0).build();
        assert!(matches!(large, Err(Error::Usage(_))));
        // Not a multiple of 128.
        let misaligned = ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 200, 0).build();
        assert!(matches!(misaligned, Err(Error::Usage(_))));
    }

    #[test]
    fn thin_pool_valid_data_block_size_is_accepted() {
        assert!(ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 128, 0).build().is_ok());
        assert!(ThinPool::builder(DevId::new(252, 1), DevId::new(252, 2), 2_097_152, 0).build().is_ok());
    }
}
