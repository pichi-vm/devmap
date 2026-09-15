// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Parameters and status for the Linux device-mapper `era` target.
//!
//! Construct [`dm::Target`] and pass it to a device-mapper backend's table
//! builder. This crate describes the target; it performs no device-mapper ioctls.
//!
//! ```
//! use devmap_era::dm::Target;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let target: Target = "7:0 7:1 128".parse()?;
//! assert_eq!(target.to_string(), "7:0 7:1 128");
//! # Ok(())
//! # }
//! ```
//!
//! There are no optional features.

pub mod dm;
