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
    /// Writes and persists a hash volume, returning its handle and root digest.
    ///
    /// Implemented for [`crate::Scheme`]. Data geometry supplies the protected
    /// block size and count; output geometry supplies the hash-block size.
    /// Position input at its beginning. Exactly the exposed extent is read.
    /// Use [`Scale::scale_to`] and regions to select sizes and extents.
    ///
    /// Writes output from byte zero. Header-based I/O accepts power-of-two
    /// block sizes from 512 bytes through 512 KiB, a nonzero count, and extents
    /// fitting in `u64` bytes. Fixed output must fit the image; growable output
    /// expands as needed. Configuration is checked before writing.
    ///
    /// Output is flushed and then persisted with [`SyncData::sync_data`].
    /// The UUID identifies the volume; it does not authenticate it. Keep the
    /// returned root independently trusted. Data-input persistence remains
    /// the caller's responsibility. Failure can leave partial output and
    /// advance either stream, but returns no completed handle or root.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for incompatible geometry or header limits,
    /// `UnexpectedEof` for short input, and `Unsupported` for an unavailable
    /// hashing implementation. Other errors come from I/O or persistence.
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
    /// Opens a userspace view using these options and an independently trusted root.
    ///
    /// Implemented for [`crate::Options`]. Pass an opened [`crate::Hashes`].
    /// Stored block sizes must be multiples of the backing block sizes, and
    /// both endpoints must fit the layout. Use regions for embedded volumes.
    ///
    /// Opening authenticates no blocks. [`crate::Verity`] applies the selected
    /// read policies lazily, with strict verification by default.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for a wrong root length or incompatible options,
    /// `InvalidData` for incompatible geometry or insufficient capacity, and
    /// `Unsupported` for kernel-only settings, FEC, or a tree start other than 1.
    /// Other errors come from storage or allocating first-read tracking state.
    fn open(
        self,
        data: D,
        hashes: crate::Hashes<H>,
        root_digest: &[u8],
    ) -> io::Result<crate::Verity<D, H>>;
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
