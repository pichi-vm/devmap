// SPDX-License-Identifier: Apache-2.0

//! Shared values and errors for device-mapper target parameters and status.
//!
//! Decode fields with [`std::str::FromStr`] and encode them with
//! [`std::fmt::Display`]. Format crates compose these into complete target
//! descriptions and use [`Error`] to report malformed text.

mod devid;
mod empty;
mod error;
mod fraction;

pub use devid::DevId;
pub use empty::Empty;
pub use error::Error;
pub use fraction::Fraction;
