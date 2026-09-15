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
    /// Consumes the input's declared extent, writes the hash device from block
    /// zero, and returns the root digest.
    ///
    /// The input's block size and count determine the protected extent. It
    /// must yield exactly that many bytes, forming one or more complete
    /// blocks. Bytes
    /// after that extent remain unread. The hash output's block size becomes
    /// the hash-block size. The output must have
    /// enough capacity for the complete image; a growable file expands as
    /// needed. It is flushed before this method returns, but is not made
    /// persistent. On error, output may be partial and either stream may have
    /// advanced.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for incompatible endpoint
    /// geometry, [`io::ErrorKind::UnexpectedEof`] when input ends before its
    /// reported extent, and
    /// [`io::ErrorKind::Unsupported`] when the selected algorithm's Cargo
    /// feature is disabled. Other errors come from the streams.
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
    /// The hash endpoint must already be opened as [`crate::Hashes`]. Each stored block size must be
    /// a multiple of the corresponding endpoint's block size, and both
    /// endpoints must contain the complete declared layout. Use a
    /// [`devmap_core::Region`] when a device occupies only part of another
    /// object.
    ///
    /// Opening does not hash data or tree blocks. Each data block is authenticated
    /// against the supplied root when read; an unavailable algorithm fails then.
    /// The returned device is positioned at logical byte zero.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for a root digest of the wrong
    /// length, [`io::ErrorKind::InvalidData`] for incompatible geometry or
    /// endpoints shorter than the declared layout. Other errors come from the endpoints.
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
    /// [`io::ErrorKind::InvalidData`] for invalid fields or overflowing
    /// layouts, or an underlying I/O error. Storage is never written.
    fn open(storage: H) -> io::Result<Self>;
}
