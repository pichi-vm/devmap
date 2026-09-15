// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! A seekable copy-on-write layer using the dm-snapshot persistent COW format.
//!
//! [`Layer`] presents an origin and a COW store as one byte stream. Reads use
//! the COW where a chunk has changed and the origin everywhere else. Writes
//! update only the COW. The format is compatible with Linux dm-snapshot; this
//! crate does not create or activate device-mapper devices.
//!
//! # Creating and using a layer
//!
//! The COW must be sized before construction. Its length controls how many
//! changed chunks it can hold. [`traits::std::Create::create`] initializes
//! metadata only; it neither reads origin data nor clears unused COW storage.
//!
//! ```
//! use std::io::{Cursor, Read, Seek, SeekFrom, Write};
//! use std::num::NonZeroU32;
//! use devmap_snapshot::{Layer, traits::std::*};
//!
//! # fn main() -> std::io::Result<()> {
//! let mut origin = Cursor::new(vec![0x11; 32 * 1024]);
//! let mut cow = Cursor::new(vec![0; 64 * 1024]);
//!
//! {
//!     let chunk_size = NonZeroU32::new(32).unwrap();
//!     let mut layer = Layer::create(&mut origin, &mut cow, chunk_size)?;
//!     layer.seek(SeekFrom::Start(20 * 1024))?;
//!     layer.write_all(b"snapshot")?;
//!     layer.sync_data()?;
//! }
//!
//! let mut layer = Layer::open(&mut origin, &mut cow)?;
//! layer.seek(SeekFrom::Start(20 * 1024))?;
//! let mut value = [0; 8];
//! layer.read_exact(&mut value)?;
//! assert_eq!(&value, b"snapshot");
//! # Ok(())
//! # }
//! ```
//!
//! Import the synchronous operation trait for each operation used:
//! [`traits::std::Create`], [`traits::std::Open`], [`traits::std::Merge`], or
//! [`traits::std::Compact`]. With the `tokio` feature, import the corresponding
//! trait from `traits::tokio` and await the same method name. The resulting
//! type uses either the standard I/O traits or Tokio's I/O traits according to
//! its endpoints.
//!
//! # Storage requirements
//!
//! The origin's length becomes the layer's length and need not be a whole
//! number of chunks. The COW must be preallocated to at least two whole chunks.
//! Its available space limits how many changed chunks can be stored; a write
//! that exceeds that capacity returns [`std::io::ErrorKind::StorageFull`].
//!
//! A requested chunk size is expressed in 512-byte sectors. It must be a power
//! of two accepted by dm-snapshot and a multiple of both endpoints' block
//! sizes. The COW length must be a whole number of the selected chunks.
//!
//! Construction obtains each endpoint's block size and block count through
//! [`traits::std::Geometry`]. Opening validates the header and exception
//! metadata, without reading stored data chunks. Pass endpoints by mutable
//! reference when the caller needs to retain ownership after dropping the layer.
//!
//! # Writes and persistence
//!
//! The first change to an origin chunk copies that entire chunk into the COW.
//! For a chunk not yet in the COW, a written range that already matches the
//! origin allocates no space. Once a chunk exists in the COW, subsequent
//! writes update it directly.
//!
//! [`std::io::Write::flush`] completes pending layer writes so they are visible
//! after reopening the COW, but does not make them durable. Call
//! `SyncData::sync_data(&mut layer)` when all completed writes must survive
//! loss of volatile caches. Dropping a layer does not flush or persist it.
//!
//! A cancelled Tokio read, write, or merge remains pending in the layer. Resume
//! the same operation before starting a conflicting one. A resumed read needs
//! at least as much buffer space as the original read, and a resumed write must
//! provide the same bytes. Cancelling `Create` or `Open` consumes owned
//! endpoints and may change their contents or positions. Cancelling `Compact`
//! may leave partial output; a new call restarts compaction.
//!
//! # Compacting and merging
//!
//! [`traits::std::Compact::compact`] writes a sequential, exact-size COW
//! containing only chunks that differ from the origin. The result begins at the
//! output's current position. For a standalone COW file, use an empty or
//! truncated output positioned at byte zero. The result has no spare capacity;
//! extend it by whole chunks before opening it for writes.
//!
//! [`traits::std::Merge::merge`] copies every changed chunk into the origin and
//! then empties the COW. Both endpoints must be exclusively accessible and
//! writable. The operation persists the origin before marking the COW empty,
//! so it can be retried after interruption. The traits in `traits::tokio`
//! provide the same operations asynchronously.
//!
//! # Run-time layer depth
//!
//! A concrete stack has a different Rust type at every depth. Use
//! [`traits::std::Readable`] when the number of layers is known only at run
//! time:
//!
//! ```
//! use std::io::Cursor;
//! use std::num::NonZeroU32;
//! use devmap_snapshot::{Layer, traits::std::*};
//!
//! # fn main() -> std::io::Result<()> {
//! let mut source: Box<dyn Readable> =
//!     Box::new(Cursor::new(vec![0; 32 * 1024]));
//!
//! for _ in 0..3 {
//!     let cow = Cursor::new(vec![0; 64 * 1024]);
//!     let chunk_size = NonZeroU32::new(32).unwrap();
//!     source = Box::new(Layer::create(source, cow, chunk_size)?);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Use [`traits::std::Readable`] for a read-only erased layer and
//! [`traits::std::Writable`] when an erased lower layer must receive a merge.
//! Keep the outermost [`Layer`] concrete when it must accept ordinary writes.
//! Tokio provides the same boundaries in `traits::tokio`.
//!
//! [`Formatter`] computes COW capacity; [`traits::std::Create::create`] formats
//! the preallocated store. File import and sparse-file traversal belong to the
//! caller, which can seek and write through the layer using ordinary I/O.
//! With a `devmap_zero::Zero` origin, skipped ranges read as zeroes, and writes
//! of zero bytes to unallocated chunks need no COW space.
//! The [`dm`] module provides device-mapper target types and codecs in every build.
//!
//! # Cargo features
//!
//! There are no default features.
//!
//! - `tokio` enables `traits::tokio` and Tokio I/O and persistence
//!   implementations for [`Layer`].

mod chunk_size;
mod layer;
pub mod traits;

pub use layer::Layer;

/// Device-mapper snapshot target parameters and runtime status.
pub mod dm;

mod formatter;
pub use formatter::Formatter;
