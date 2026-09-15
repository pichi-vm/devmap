// SPDX-License-Identifier: Apache-2.0

//! Shared values and errors for device-mapper target parameters and status.
//!
//! [`DevId`] represents a `major:minor` device identifier, [`Fraction`] represents
//! two values encoded as `a/b`, and [`NoInfo`] validates an empty status response.
//! Parse values with [`std::str::FromStr`] and format them with
//! [`std::fmt::Display`]. Target crates also use [`Error`] for malformed
//! parameter and status strings.
//!
//! ```
//! use devmap_core::parse::{DevId, Error, Fraction, NoInfo};
//!
//! # fn main() -> Result<(), Error> {
//! let device: DevId = "7:1".parse()?;
//! let usage: Fraction<u64> = "12/64".parse()?;
//! let empty: NoInfo = "".parse()?;
//! assert_eq!(device.to_string(), "7:1");
//! assert_eq!(<(u64, u64)>::from(usage), (12, 64));
//! assert_eq!(empty.to_string(), "");
//! # Ok(())
//! # }
//! ```

mod dev_id;
mod error;
mod fraction;
mod no_info;

pub use dev_id::DevId;
pub use error::Error;
pub use fraction::Fraction;
pub use no_info::NoInfo;
