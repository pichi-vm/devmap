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
    /// Uses the same sizing, alignment, and flushing contracts. Cancellation
    /// may leave partial output and advance either stream.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as
    /// [`crate::traits::std::Format::format`].
    fn format(
        self,
        data: D,
        hashes: H,
        uuid: [u8; 16],
    ) -> impl Future<Output = io::Result<(crate::Hashes<H>, Box<[u8]>)>> + Send;
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
    /// Uses the same layout, alignment, and authentication contracts.
    /// Cancellation may advance either stream.
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
    /// Asynchronous form of [`crate::traits::std::OpenHashes::open`].
    ///
    /// Uses the same validation and final stream position. Failure or
    /// cancellation may advance the stream. Storage is never written.
    ///
    /// # Errors
    ///
    /// Returns the same error kinds as [`crate::traits::std::OpenHashes::open`].
    fn open(storage: H) -> impl Future<Output = io::Result<Self>> + Send;
}
