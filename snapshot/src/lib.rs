// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! The dm-snapshot persistent copy-on-write store, byte-exact per
//! `drivers/md/dm-snap-persistent.c`.
//!
//! A [`Layer`] is a seekable byte stream over an origin and persistent COW.
//! It implements the standard [`Read`](std::io::Read),
//! [`Write`](std::io::Write), and [`Seek`](std::io::Seek) traits. With the
//! `tokio` feature, the same type implements Tokio's corresponding traits.
//! Layers can nest because they use those established byte-stream protocols.
//!
//! This crate does not create or activate device-mapper devices.
//!
//! # Layout
//!
//! ```text
//! chunk 0:                     header
//! chunk 1:                     metadata area 0
//! chunks 2..2 + entries:       data area 0
//! chunk 2 + entries:           metadata area 1
//! ...
//! ```
//!
//! where `entries` is `chunk_bytes / 16`. All multi-byte fields are
//! little-endian, and every index is a chunk index, not a sector index. A
//! `new_chunk` of 0 ends the exception list, since chunk 0 holds the header.
//!
//! [`convert`] writes a raw image into a new store over a zero origin:
//!
//! ```
//! use devmap_snapshot::{ChunkSize, convert};
//! use std::io::Cursor;
//!
//! # fn main() -> std::io::Result<()> {
//! let image = vec![0xa5; 3 * 4096];
//! let mut cow = Cursor::new(Vec::new());
//!
//! let chunk_size = ChunkSize::from_sectors(8)?;
//! let converted = convert(&image[..], image.len() as u64, &mut cow, chunk_size)?;
//!
//! assert_eq!(converted.exception_count, 3);
//! # Ok(())
//! # }
//! ```
//!
//! [`SyncData`] is the persistence boundary used to order data before the
//! metadata that points to it. It is deliberately distinct from
//! [`std::io::Write::flush`], which only drains transport buffering.

mod chunk_size;
mod convert;
mod durability;
mod layer;
mod merge;

pub use chunk_size::ChunkSize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use convert::convert_sparse;
pub use convert::{Conversion, convert};
#[cfg(feature = "tokio")]
pub use durability::AsyncSyncData;
pub use durability::SyncData;
pub use layer::Layer;
pub use merge::Merge;
