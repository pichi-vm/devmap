// SPDX-License-Identifier: Apache-2.0

//! Standard-library synchronous operations.

use std::io;

pub use devmap_core::traits::std::{Geometry, Scale, Slice, SliceBytes, SyncData};

/// Formats a dm-verity hash device.
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
    /// Writes a hash device from byte zero and returns its root digest.
    ///
    /// Input geometry defines the protected extent: one or more complete
    /// blocks. Exactly that extent is consumed; trailing bytes remain unread.
    /// Output geometry supplies the hash-block size. Fixed storage must fit
    /// the complete image; growable storage expands as needed.
    ///
    /// Output is flushed, not persisted. For durable output, retain it by
    /// passing `&mut` and call [`SyncData::sync_data`] after formatting.
    /// Failure may leave partial output and advance either stream.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for incompatible endpoint
    /// geometry, [`io::ErrorKind::UnexpectedEof`] for short input, or
    /// [`io::ErrorKind::Unsupported`] for a disabled hash implementation.
    /// Other errors come from the streams.
    fn format(self, data: D, hashes: H) -> io::Result<Box<[u8]>>;
}

/// Opens a dm-verity device using an externally trusted root digest.
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
    /// Checks endpoint geometry and the supplied root digest's length.
    ///
    /// Pass an opened [`crate::Hashes`]. Each stored block size must be a
    /// multiple of its backing storage's block size, and both devices must
    /// fit the declared layout. Use [`Region`](devmap_core::Region) for embedded devices.
    ///
    /// The view starts at logical byte zero. Opening authenticates no blocks;
    /// [`crate::Verity`] checks them on read.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a root digest of the wrong
    /// length, [`io::ErrorKind::InvalidData`] for incompatible geometry or
    /// storage shorter than the declared layout. Other errors come from storage.
    fn open(data: D, hashes: H, root_digest: &[u8]) -> io::Result<Self>;
}

/// Opens a hash device without requiring data storage or hashing support.
pub trait OpenHashes<H>: Sized {
    /// Reads and validates the 512-byte header at byte zero.
    ///
    /// On success the backing stream is positioned at byte 512. No tree
    /// blocks, hash-block padding, or endpoint geometry are inspected.
    /// Known algorithm names are accepted regardless of hashing features.
    /// Pass a zero-based region for a format embedded in a larger object.
    /// Failure may change the stream position.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] for a short header,
    /// [`io::ErrorKind::InvalidData`] for unknown formats or algorithms, invalid
    /// fields, nonzero record padding, or overflowing layouts. Other errors
    /// come from storage, which is never written.
    fn open(storage: H) -> io::Result<Self>;
}
