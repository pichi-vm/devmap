// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! A finite zero-filled byte stream and a Linux device-mapper target description.
//!
//! [`Zero`] supplies zero bytes without allocating backing storage. It supports
//! standard reads, seeks, and [`devmap_core::traits::std::Geometry`]. This crate
//! does not create kernel devices or issue device-mapper ioctls.
//!
//! ```
//! use devmap_zero::Zero;
//! use std::io::{Read, Seek, SeekFrom};
//!
//! # fn main() -> std::io::Result<()> {
//! let mut device = Zero::new(4096);
//! device.seek(SeekFrom::End(-2))?;
//! let mut bytes = [1; 2];
//! device.read_exact(&mut bytes)?;
//! assert_eq!(bytes, [0, 0]);
//! assert_eq!(device.read(&mut bytes)?, 0);
//! # Ok(())
//! # }
//! ```
//!
//! Reads stop at the configured length. Seeking beyond the end is allowed;
//! seeking before byte zero is rejected. [`Zero`] does not implement writes.
//!
//! [`dm::ZeroTarget`] describes the kernel zero target, which returns zeroes for
//! reads and discards writes. Pass it to a device-mapper backend's table builder.
//!
//! # Cargo features
//!
//! There are no default features. The optional `tokio` dependency adds Tokio
//! reads, seeks, and asynchronous geometry to the same [`Zero`] type.

pub mod dm;
mod zero;

pub use zero::Zero;
