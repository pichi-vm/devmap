// SPDX-License-Identifier: Apache-2.0

//! Tokio asynchronous operations.

use std::future::Future;
use std::io;

pub use devmap_core::traits::tokio::{Geometry, Scale, Slice, SliceBytes, SyncData};

/// Formats a dm-verity hash device asynchronously.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "ripemd",
        feature = "whirlpool",
        feature = "streebog",
        feature = "sm3",
        feature = "blake2"
    )))
)]
pub trait Format<D, H>: Sized {
    /// Asynchronously performs the same operation as
    /// [`crate::traits::std::Format::format`].
    ///
    /// See the synchronous operation for its sizing, alignment, and flushing
    /// contracts. Cancellation may leave partial output, advance either
    /// stream, and drop values passed by ownership; borrowed streams are
    /// released.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as
    /// [`crate::traits::std::Format::format`].
    fn format(self, data: D, hashes: H) -> impl Future<Output = io::Result<Box<[u8]>>> + Send;
}

/// Opens a dm-verity device asynchronously.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "ripemd",
        feature = "whirlpool",
        feature = "streebog",
        feature = "sm3",
        feature = "blake2"
    )))
)]
pub trait Open<D, H>: Sized {
    /// Asynchronously performs the same validation as
    /// [`crate::traits::std::Open::open`].
    ///
    /// See the synchronous operation for its layout, alignment, and
    /// authentication contracts. Cancellation may advance either endpoint
    /// and drop values passed by ownership; borrowed endpoints are released.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as [`crate::traits::std::Open::open`].
    fn open(
        data: D,
        hashes: H,
        root_digest: &[u8],
    ) -> impl Future<Output = io::Result<Self>> + Send;
}

/// Opens a hash device without requiring data storage or hashing support.
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait OpenHashes<H>: Sized {
    /// Reads and validates the 512-byte header at byte zero.
    ///
    /// On success the backing stream is positioned at byte 512. No tree
    /// blocks, hash-block padding, or endpoint geometry are inspected.
    /// Known algorithm names are accepted regardless of hashing features.
    /// Pass a zero-based region for a format embedded in a larger object.
    /// Failure or cancellation may advance the stream and drops owned endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] for a short header,
    /// [`io::ErrorKind::InvalidData`] for invalid fields or overflowing
    /// layouts, or an underlying I/O error. Storage is never written.
    fn open(storage: H) -> impl Future<Output = io::Result<Self>> + Send;
}
