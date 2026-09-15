// SPDX-License-Identifier: Apache-2.0

//! Traits for standard-library synchronous I/O.

use std::io::{self, Read, Seek, Write};
use std::num::NonZeroU32;

pub use devmap_core::traits::std::{Geometry, Scale, Slice, SliceBytes, SyncData};

/// An object-safe, read-only layer endpoint.
///
/// Use this trait when a collection can contain either backing devices or
/// nested [`crate::Layer`] values. It provides the operations needed to read
/// and position a layer and inspect its geometry.
pub trait Readable: Read + Seek + Geometry {}

impl<T: Read + Seek + Geometry + ?Sized> Readable for T {}

/// An object-safe, writable layer endpoint.
///
/// In addition to [`Readable`], this permits writes and data persistence. A
/// writable origin is required only by [`Merge`].
pub trait Writable: Readable + Write + SyncData {}

impl<T: Readable + Write + SyncData + ?Sized> Writable for T {}

/// Creates a copy-on-write layer.
pub trait Create<O, C>: Sized {
    /// Initializes `cow` and returns an empty layer over `origin`.
    ///
    /// Replaces the COW metadata with an empty snapshot; existing exceptions
    /// become inaccessible. Origin data is neither read nor modified, and
    /// unused COW data chunks are not erased. The returned layer is positioned
    /// at byte zero.
    ///
    /// `chunk_size` is measured in 512-byte sectors. It must be compatible
    /// with both endpoints' block sizes. `cow` must contain at least
    /// two whole chunks. An error may leave the COW partially initialized.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for incompatible geometry.
    /// Other errors come from inspecting the endpoints or initializing the
    /// COW.
    fn create(origin: O, cow: C, chunk_size: NonZeroU32) -> io::Result<Self>;
}

/// Opens an existing copy-on-write layer.
pub trait Open<O, C>: Sized {
    /// Reads and validates the COW header and exception metadata before returning.
    ///
    /// Stored data chunks are not read or authenticated. Neither endpoint is
    /// written. The returned layer is positioned at byte zero.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] for a malformed or incompatible
    /// COW. Other errors come from the endpoints.
    fn open(origin: O, cow: C) -> io::Result<Self>;
}

/// Merges a layer into its origin.
pub trait Merge {
    /// Copies changed chunks to the origin and empties the COW.
    ///
    /// The origin is persisted before the COW is marked empty, so an
    /// interrupted merge can be retried.
    ///
    /// # Errors
    ///
    /// Returns an endpoint error if data cannot be copied, flushed, or
    /// persisted. The source store can be reopened and retried.
    fn merge(&mut self) -> io::Result<()>;
}

/// Writes a compact representation of a layer's COW.
pub trait Compact {
    /// Writes a sequential, exact-size COW to `output`.
    ///
    /// Exceptions equal to the origin are omitted. The representation begins
    /// at the output's current position, so an independent file intended to
    /// contain only the result should be empty or truncated and positioned at
    /// byte zero. The output must not alias either endpoint. It is flushed
    /// before this method returns.
    ///
    /// # Errors
    ///
    /// Returns an endpoint error. The source remains usable, but the output
    /// may be incomplete.
    fn compact(&mut self, output: impl Write) -> io::Result<()>;
}
