// SPDX-License-Identifier: Apache-2.0

//! The `era` target: tracks which blocks of an origin device have changed
//! since a given "era", for incremental backup.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// Tracks which blocks of `origin` have changed since which "era", for
/// incremental backup. Era rollover/snapshot control is message-driven
/// — see [`crate::Device::message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Era {
    metadata: DevId,
    origin: DevId,
    block_size: u32,
}
impl Era {
    /// Construct an [`Era`].
    #[must_use]
    pub fn new(metadata: DevId, origin: DevId, block_size: u32) -> Self {
        Era {
            metadata,
            origin,
            block_size,
        }
    }

    /// Device holding the era metadata (the change map).
    #[must_use]
    pub fn metadata(&self) -> DevId {
        self.metadata
    }
    /// The origin device whose changes are tracked.
    #[must_use]
    pub fn origin(&self) -> DevId {
        self.origin
    }
    /// Tracking granularity, in 512-byte sectors per block.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
}
impl Target for Era {
    const TYPE_NAME: &'static str = "era";
    type Info = RawInfo;
}
impl fmt::Display for Era {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.metadata, self.origin, self.block_size)
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
    fn era_renders_metadata_origin_and_block_size() {
        let t = Era::new(DevId::new(252, 1), DevId::new(252, 2), 128);
        assert_eq!(line(0, 8192, &t), "0 8192 era 252:1 252:2 128");
    }
}
