// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! Storage capabilities, I/O adapters, and shared device-mapper interfaces.
//!
//! [`traits::std::Geometry`] describes a device with a block size in bytes and
//! a block count. Device addresses begin at block zero; multiplying those two
//! values gives the complete byte extent. This crate defines no on-disk formats
//! or concrete targets and performs no device-mapper control ioctls.
//!
//! # Basic use
//!
//! ```
//! use std::io::{Cursor, Read, Seek, SeekFrom};
//! use std::num::NonZeroU32;
//! use devmap_core::traits::std::{Geometry as _, Scale as _, Slice as _};
//!
//! # fn main() -> std::io::Result<()> {
//! let source = Cursor::new(vec![0; 8192])
//!     .scale_to(NonZeroU32::new(4096).unwrap())?;
//! let mut source = source.slice(1..)?;
//! assert_eq!(source.block_size()?.get(), 4096);
//! assert_eq!(source.count()?, 1);
//! source.seek(SeekFrom::End(-2))?;
//! let mut tail = [1; 2];
//! source.read_exact(&mut tail)?;
//! assert_eq!(tail, [0, 0]);
//! # Ok(())
//! # }
//! ```
//!
//! [`traits::std::Scale::scale`] increases the block size by a power-of-two
//! multiplier without changing the byte extent; [`traits::std::Scale::scale_to`]
//! instead takes the desired block size in bytes.
//! [`traits::std::Slice::slice`] selects blocks using `(start, count)` or any
//! standard range type. The returned [`Region`] starts at block zero and
//! confines I/O to the selected extent. Use [`traits::std::SliceBytes::slice_bytes`]
//! for aligned byte ranges and [`traits::std::Geometry::byte_size`] for the
//! complete extent in bytes. Neither adapter resizes storage.
//!
//! Import [`traits::std`] for synchronous I/O. Enabling Tokio provides a
//! matching `traits::tokio` module; operations that can perform asynchronous
//! I/O additionally require `.await`. `SyncData` in either module is a
//! persistence boundary and is stronger than flushing a writer.
//!
//! # Device-mapper interfaces
//!
//! [`Target`] describes a target's kernel name and table/status types. [`DevId`]
//! identifies a backing device by its major and minor numbers. Row ranges use
//! 512-byte sectors; their start, length, and whole-table access mode remain separate
//! from target arguments. Concrete targets belong to their format crates and
//! can be passed to a backend such as `devmap-linux`.
//!
//! Target fields use [`std::str::FromStr`] for parsing. [`Fraction`] handles
//! the `a/b` syntax used for usage counts and progress without interpreting the
//! relationship between the values. [`NoInfo`] validates empty status text,
//! while [`String`] preserves arbitrary status text without validation.
//!
//! Table construction, access mode, device creation, activation, removal, and
//! messages belong to the backend.
//!
//! # Cargo features
//!
//! There are no default features.
//!
//! - `tokio` provides the Tokio traits, implements them for
//!   `tokio::fs::File`, and enables Tokio I/O on the adapters.

mod dm;
mod durability;
mod geometry;
pub mod traits;
#[cfg(target_os = "linux")]
mod uapi;

pub use dm::{DevId, Fraction, NoInfo, ParseError, Target};
pub use geometry::{Region, Scaled};
