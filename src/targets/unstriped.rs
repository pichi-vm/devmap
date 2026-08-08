// SPDX-License-Identifier: Apache-2.0

//! The `unstriped` target: exposes a single stripe of an existing
//! striped/RAID0 mapping as its own device.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// Exposes one stripe of an existing striped/RAID0 mapping as its own
/// device, for per-stripe `QoS` isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unstriped {
    /// The total number of stripes in the underlying mapping.
    ///
    /// The kernel enforces the value rules on table load: `stripes` and
    /// `chunk_size_sectors` must be nonzero, and `stripe_index` must be
    /// less than `stripes`.
    pub stripes: u32,
    /// The chunk size in sectors.
    pub chunk_size_sectors: u32,
    /// The index of the exposed stripe.
    pub stripe_index: u32,
    /// The backing device.
    pub device: DevId,
    /// The starting offset in sectors.
    pub offset_sectors: u64,
}
impl Target for Unstriped {
    const NAME: &'static str = "unstriped";
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
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {params}", T::NAME)
        }
    }

    #[test]
    fn unstriped_renders_all_fields() {
        let t = Unstriped {
            stripes: 2,
            chunk_size_sectors: 256,
            stripe_index: 0,
            device: DevId::new(252, 1).unwrap(),
            offset_sectors: 0,
        };
        assert_eq!(line(0, 512, &t), "0 512 unstriped 2 256 0 252:1 0");
    }
}
