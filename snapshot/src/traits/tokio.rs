// SPDX-License-Identifier: Apache-2.0

//! Traits for Tokio asynchronous I/O.

use std::future::Future;
use std::io;
use std::num::NonZeroU32;

pub use devmap_core::traits::tokio::{Geometry, Scale, Slice, SliceBytes, SyncData};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

/// An object-safe, read-only layer endpoint.
///
/// Use this trait when a collection can contain either backing devices or
/// nested [`crate::Layer`] values. It provides the operations needed to read
/// and position a layer and inspect its geometry.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Readable: AsyncRead + AsyncSeek + Geometry + Unpin + Send {}

impl<T> Readable for T where T: AsyncRead + AsyncSeek + Geometry + Unpin + Send + ?Sized {}

/// An object-safe, writable layer endpoint.
///
/// In addition to [`Readable`], this permits writes and data persistence. A
/// writable origin is required only by [`Merge`].
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Writable: Readable + AsyncWrite + SyncData {}

impl<T: Readable + AsyncWrite + SyncData + ?Sized> Writable for T {}

/// Creates a copy-on-write layer.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
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
    /// two whole chunks. An error or cancellation may leave it partially
    /// initialized and may change either endpoint's position.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as
    /// [`crate::traits::std::Create::create`].
    fn create(
        origin: O,
        cow: C,
        chunk_size: NonZeroU32,
    ) -> impl Future<Output = io::Result<Self>> + Send;
}

/// Opens an existing copy-on-write layer.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Open<O, C>: Sized {
    /// Reads and validates the COW header and exception metadata before returning.
    ///
    /// Stored data chunks are not read or authenticated. Neither endpoint is
    /// written. The returned layer is positioned at byte zero. Cancellation
    /// may change an endpoint's stream position.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as [`crate::traits::std::Open::open`].
    fn open(origin: O, cow: C) -> impl Future<Output = io::Result<Self>> + Send;
}

/// Merges a layer into its origin.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Merge {
    /// Copies changed chunks to the origin and empties the COW.
    ///
    /// A cancelled operation remains in the layer; call `merge` again to
    /// resume it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`crate::traits::std::Merge::merge`].
    fn merge(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Writes a compact representation of a layer's COW.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait Compact {
    /// Writes a sequential, exact-size COW to `output`.
    ///
    /// The representation begins at the output's current position.
    /// Cancellation may leave partial output but does not modify the source
    /// layer.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`crate::traits::std::Compact::compact`].
    fn compact(
        &mut self,
        output: impl AsyncWrite + Unpin + Send,
    ) -> impl Future<Output = io::Result<()>> + Send;
}
