// SPDX-License-Identifier: Apache-2.0

//! Shared device-mapper target descriptions and field codecs.
//!
//! Row start/length and whole-table access mode are supplied separately from
//! target-specific arguments. This module performs no device-mapper ioctls.

mod device;
mod error;
mod fraction;
mod info;
mod target;

pub use device::DevId;
pub use error::ParseError;
pub use fraction::Fraction;
pub use info::NoInfo;
pub use target::Target;
