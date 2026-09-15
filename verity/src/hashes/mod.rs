// SPDX-License-Identifier: Apache-2.0

use crate::superblock::Header;

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
mod authentication;
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
    header: Header,
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
    fn new(inner: H, header: Header) -> Self {
        Self {
            inner,
            header,
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

    /// Borrows the validated header without performing I/O.
    ///
    /// Available even while an asynchronous read is pending.
    pub const fn header(&self) -> &Header {
        &self.header
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
