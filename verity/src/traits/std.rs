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
    /// Writes a header and tree, returning their handle and root digest.
    ///
    /// Implemented for [`crate::Parameters`]. Reads exactly the declared data
    /// extent from the current input position; trailing bytes remain unread.
    /// Each configured block size must be a multiple of the endpoint's block
    /// size. Writes hash storage from byte zero. Fixed storage must fit the
    /// image; growable storage expands as needed. The UUID identifies the
    /// volume but does not authenticate it.
    ///
    /// Header-based formatting accepts block sizes up to 512 KiB and salts
    /// up to 256 bytes. Extents must fit in `u64` bytes. Configuration is
    /// checked before writing.
    ///
    /// Output is flushed, not persisted. Call [`SyncData::sync_data`] on the
    /// returned handle for durability. Keep the root in independently trusted
    /// storage. Failure may leave partial output and advance either stream;
    /// no completed handle or root is returned.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for incompatible endpoint
    /// geometry or unrepresentable header fields, [`io::ErrorKind::UnexpectedEof`] for short input, or
    /// [`io::ErrorKind::Unsupported`] for a disabled hash implementation.
    /// Other errors come from the streams.
    fn format(
        self,
        data: D,
        hashes: H,
        uuid: [u8; 16],
    ) -> io::Result<(crate::Hashes<H>, Box<[u8]>)>;
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
