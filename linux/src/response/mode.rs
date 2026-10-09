// SPDX-License-Identifier: Apache-2.0

use crate::target::{Parse, Target};

/// `STATUSTYPE_TABLE`: the mapping's construction parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Table {}

/// `STATUSTYPE_INFO`: per-target runtime information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Info {}

mod sealed {
    pub trait Sealed {}
}

/// Associates a response mode with the corresponding type from a [`Target`].
///
/// This trait is sealed; the supported modes are [`Table`] and [`Info`].
pub trait Mode: sealed::Sealed {
    /// Type produced for target family `T` in this response mode.
    type Parsed<T: Target>: Parse;
}

impl sealed::Sealed for Table {}

impl Mode for Table {
    type Parsed<T: Target> = T::Table;
}

impl sealed::Sealed for Info {}

impl Mode for Info {
    type Parsed<T: Target> = T::Info;
}
