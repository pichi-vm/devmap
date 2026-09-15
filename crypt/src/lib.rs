// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Parameters and status for the Linux device-mapper `crypt` target.
//!
//! Construct [`dm::CryptTarget`] and pass it to a device-mapper backend's table
//! builder. This crate describes the target; it performs no device-mapper ioctls.
//!
//! ```
//! use devmap_crypt::dm::CryptTarget;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let target: CryptTarget = "aes-xts-plain64 :64:logon:example:volume 0 7:0 0".parse()?;
//! assert_eq!(target.to_string(), "aes-xts-plain64 :64:logon:example:volume 0 7:0 0");
//! # Ok(())
//! # }
//! ```
//!
//! Table text containing a raw key is sensitive; do not log it.
//! There are no optional features.

pub mod dm;
