// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Target parameters, header inspection, and formatting for dm-integrity.
//!
//! Construct [`dm::Target`] and pass it to a device-mapper backend's table
//! builder. [`dm::Target::format`] uses a caller-supplied backend to initialize
//! storage through a temporary mapping. This crate implements neither
//! device-mapper ioctls nor userspace integrity-tag I/O.
//!
//! ```
//! use devmap_integrity::dm::{Target, Mode};
//! use devmap_core::DevId;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let target = Target::builder(DevId::new(7, 0).unwrap(), 0, Mode::Journaled)
//!     .tag_size(16).internal_hash("crc32c").build();
//! assert_eq!(target.to_string(), "7:0 0 16 J 1 internal_hash:crc32c");
//! # Ok(())
//! # }
//! ```
//!
//! # Inspecting and formatting storage
//!
//! [`Header::open`] reads the superblock prefix from byte zero and exposes the
//! recorded capacity in 512-byte sectors. It does not validate the journal,
//! integrity tags, or protected data.
//!
//! [`dm::Target::format`] is destructive: it clears and persists the superblock,
//! asks a backend implementing [`devmap_core::Control`] to initialize a
//! temporary mapping, requests its removal, and returns the usable sector
//! count. The backing path must identify the target's device, and the caller
//! must ensure exclusive access. Failure can leave partially initialized
//! storage; a cleanup failure also identifies the remaining temporary mapping.
//!
//! # Cargo features
//!
//! There are no optional features.

pub mod dm;

mod header;
pub use header::Header;
