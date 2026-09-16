// SPDX-License-Identifier: Apache-2.0

use crate::{Scheme, Shape, layout::Layout};

#[cfg(feature = "tokio")]
mod r#async;
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
pub(crate) mod authentication;
mod sync;

/// An opened dm-verity hash device with validated metadata.
///
/// Open with [`crate::traits::std::OpenHashes`] or its Tokio counterpart.
/// Opening reads only the header; it neither authenticates the tree nor checks
/// storage geometry or capacity.
///
/// The backing contents must remain unchanged while this handle is in use.
/// Pass an adapter as the backing storage to select a region or add caching.
/// This type does not expose raw bytes.
#[allow(missing_debug_implementations)]
pub struct Hashes<H> {
    inner: H,
    uuid: [u8; 16],
    pub(crate) layout: Layout,
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
    authentication: Option<authentication::State>,
}

impl<H> Hashes<H> {
    // Callers validate header limits, including u64 byte extents, before construction.
    pub(crate) fn new(inner: H, uuid: [u8; 16], layout: Layout) -> Self {
        Self {
            inner,
            uuid,
            layout,
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
            authentication: None,
        }
    }

    /// Returns the stored volume UUID; it does not authenticate the contents.
    pub const fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Returns the stored hashing choices without I/O.
    pub const fn scheme(&self) -> Scheme {
        self.layout.scheme
    }

    /// Returns the stored geometry without I/O.
    pub const fn shape(&self) -> Shape {
        self.layout.shape
    }

    /// Consumes the handle and returns its backing storage.
    ///
    /// Performs no I/O or finalization. The storage's position is unspecified
    /// after authentication operations, including cancelled operations.
    #[must_use]
    pub fn into_inner(self) -> H {
        self.inner
    }
}
