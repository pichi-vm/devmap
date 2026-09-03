// SPDX-License-Identifier: Apache-2.0

use core::fmt;

/// The dm-verity hash-tree format.
///
/// This controls salt placement and digest packing. It is separate from the
/// hash [`crate::Algorithm`].
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashType {
    /// Chrome OS format (`0`).
    ///
    /// The salt follows the block. Digests use their exact length, and the
    /// number stored in each block is rounded down to a power of two.
    ChromeOs,

    /// Normal format (`1`).
    ///
    /// The salt precedes the block. Digest slots are padded to a power of two.
    #[default]
    Normal,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChromeOs => 0.fmt(f),
            Self::Normal => 1.fmt(f),
        }
    }
}
