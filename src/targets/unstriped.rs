// SPDX-License-Identifier: Apache-2.0

//! The `unstriped` target: exposes a single stripe of an existing
//! striped/RAID0 mapping as its own device.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// Exposes one stripe of an existing striped/RAID0 mapping as its own
/// device, for per-stripe `QoS` isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Unstriped {
    stripes: u32,
    chunk_size_sectors: u32,
    stripe_index: u32,
    device: DevId,
    offset_sectors: u64,
}
impl Unstriped {
    /// Construct an [`Unstriped`].
    ///
    /// Value rules (nonzero `stripes`/`chunk_size_sectors`,
    /// `stripe_index < stripes`) are enforced by the kernel on table load.
    #[must_use]
    pub fn new(
        stripes: u32,
        chunk_size_sectors: u32,
        stripe_index: u32,
        device: DevId,
        offset_sectors: u64,
    ) -> Self {
        Unstriped {
            stripes,
            chunk_size_sectors,
            stripe_index,
            device,
            offset_sectors,
        }
    }

    /// The total number of stripes in the underlying mapping.
    #[must_use]
    pub fn stripes(&self) -> u32 {
        self.stripes
    }
    /// The chunk size in sectors.
    #[must_use]
    pub fn chunk_size_sectors(&self) -> u32 {
        self.chunk_size_sectors
    }
    /// The index of the exposed stripe.
    #[must_use]
    pub fn stripe_index(&self) -> u32 {
        self.stripe_index
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
}
impl Target for Unstriped {
    const TYPE_NAME: &'static str = "unstriped";
    type Info = RawInfo;
}
impl fmt::Display for Unstriped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}",
            self.stripes,
            self.chunk_size_sectors,
            self.stripe_index,
            self.device,
            self.offset_sectors
        )
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
    fn unstriped_renders_all_fields() {
        let t = Unstriped::new(2, 256, 0, DevId::new(252, 1), 0);
        assert_eq!(line(0, 512, &t), "0 512 unstriped 2 256 0 252:1 0");
    }
}
