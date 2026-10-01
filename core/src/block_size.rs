// SPDX-License-Identifier: Apache-2.0

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::num::NonZero;

use crate::{Constraint, General};

/// A power-of-two block size governed by constraint `C`.
///
/// The value is stored as a base-two exponent. Constructors and accessors
/// explicitly identify whether their argument or result is bytes or an
/// exponent.
pub struct BlockSize<C: Constraint = General> {
    exponent: u32,
    constraint: PhantomData<C>,
}

impl<C: Constraint> BlockSize<C> {
    /// Constructs a block size from a nonzero byte count.
    ///
    /// Returns `None` unless `bytes` is a power of two whose exponent is
    /// permitted by `C`.
    pub const fn from_bytes(bytes: NonZero<u32>) -> Option<Self> {
        let bytes = bytes.get();
        if !bytes.is_power_of_two() {
            return None;
        }
        Self::from_exponent(bytes.trailing_zeros())
    }

    /// Constructs a block size from a base-two exponent.
    ///
    /// Returns `None` unless the exponent is permitted by `C` and its byte
    /// count can be represented by `u32`.
    pub const fn from_exponent(exponent: u32) -> Option<Self> {
        if exponent < C::MIN || exponent > C::MAX || 1u32.checked_shl(exponent).is_none() {
            return None;
        }
        Some(Self {
            exponent,
            constraint: PhantomData,
        })
    }

    /// Returns the block size in bytes.
    ///
    /// # Panics
    ///
    /// Panics only if the type's private exponent invariant has been violated.
    /// Every public constructor preserves the invariant.
    pub const fn bytes(self) -> NonZero<u32> {
        NonZero::new(1u32 << self.exponent).unwrap()
    }

    /// Returns the base-two exponent of the block size.
    pub const fn exponent(self) -> u32 {
        self.exponent
    }

    /// Converts this block size to another constraint.
    ///
    /// Returns `None` when the exponent is not permitted by `D`.
    pub const fn convert<D: Constraint>(self) -> Option<BlockSize<D>> {
        BlockSize::<D>::from_exponent(self.exponent)
    }
}

impl<C: Constraint> Default for BlockSize<C> {
    fn default() -> Self {
        Self::from_exponent(C::DEFAULT).expect("invalid Constraint::DEFAULT")
    }
}

impl<C: Constraint> Clone for BlockSize<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Constraint> Copy for BlockSize<C> {}

impl<C: Constraint> fmt::Debug for BlockSize<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BlockSize")
            .field(&self.bytes())
            .finish()
    }
}

impl<C: Constraint> PartialEq for BlockSize<C> {
    fn eq(&self, other: &Self) -> bool {
        self.exponent == other.exponent
    }
}

impl<C: Constraint> Eq for BlockSize<C> {}

impl<C: Constraint> PartialOrd for BlockSize<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: Constraint> Ord for BlockSize<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.exponent.cmp(&other.exponent)
    }
}

impl<C: Constraint> Hash for BlockSize<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.exponent.hash(state);
    }
}
