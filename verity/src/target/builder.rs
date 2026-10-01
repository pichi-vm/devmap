// SPDX-License-Identifier: Apache-2.0

use std::{io, num::NonZero};

use devmap_core::{BlockSize, Geometry};
use devmap_linux::DevId;

use crate::header::{Algorithm, HashType, Header, Salt};

use super::{CorruptionPolicy, IoErrorPolicy, VerityTarget};

/// Configures a Linux dm-verity target.
///
/// Create a builder with [`VerityTarget::builder`] for a headerless tree or
/// [`Header::builder`] for a tree described by an on-disk header.
/// Format metadata is kept together as a single [`Header`].
#[derive(Debug, Clone)]
pub struct Builder {
    header: Header,
    data: DevId,
    hash: DevId,
    hash_start: u64,
    root: Box<[u8]>,
    corruption_policy: CorruptionPolicy,
    io_error_policy: IoErrorPolicy,
    ignore_zero_blocks: bool,
    check_at_most_once: bool,
    try_verify_in_tasklet: bool,
    root_hash_sig_key_desc: Option<String>,
    data_sectors: u64,
    tree_size: u128,
}

impl VerityTarget {
    /// Starts a headerless target with default hashing, block sizes, and policy.
    ///
    /// The hash tree starts at hash block zero.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the root length does not
    /// match the default algorithm or the resulting layout overflows.
    pub fn builder(
        data: DevId,
        hash: DevId,
        data_blocks: NonZero<u64>,
        root: impl Into<Box<[u8]>>,
    ) -> io::Result<Builder> {
        Builder::new(data, hash, data_blocks, root)
    }
}

impl Header {
    /// Starts a target builder with this header's format metadata.
    ///
    /// The hash tree defaults to block one, immediately after a standard
    /// header block. The UUID remains in the builder but is not a dm-verity
    /// table parameter and therefore does not affect the constructed target.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the header and root do not
    /// describe a valid kernel target or the resulting layout overflows.
    pub fn builder(
        &self,
        data: DevId,
        hash: DevId,
        root: impl Into<Box<[u8]>>,
    ) -> io::Result<Builder> {
        Builder::from_header(self, data, hash, root)
    }
}

impl Builder {
    pub(super) fn new(
        data: DevId,
        hash: DevId,
        data_blocks: NonZero<u64>,
        root: impl Into<Box<[u8]>>,
    ) -> io::Result<Self> {
        Self::with_header(
            &Header {
                uuid: [0; 16],
                hash_type: HashType::default(),
                algorithm: Algorithm::default(),
                salt: Salt::default(),
                data: Geometry {
                    size: BlockSize::default(),
                    count: data_blocks,
                },
                hash: BlockSize::default(),
            },
            data,
            hash,
            0,
            root.into(),
        )
    }

    pub(super) fn from_header(
        header: &Header,
        data: DevId,
        hash: DevId,
        root: impl Into<Box<[u8]>>,
    ) -> io::Result<Self> {
        Self::with_header(header, data, hash, 1, root.into())
    }

    fn with_header(
        header: &Header,
        data: DevId,
        hash: DevId,
        hash_start: u64,
        root: Box<[u8]>,
    ) -> io::Result<Self> {
        let data_sectors = u64::try_from(header.data_bytes() / 512)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "verity layout overflows"))?;
        let hashes_per_block = header.hashes_per_block()?;
        let tree_blocks =
            header
                .level_blocks(hashes_per_block)
                .try_fold(0u128, |total, blocks| {
                    total.checked_add(u128::from(blocks)).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "verity layout overflows")
                    })
                })?;
        let tree_size = tree_blocks
            .checked_mul(u128::from(header.hash.bytes().get()))
            .filter(|size| size / 512 <= u128::from(u64::MAX))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "verity layout overflows")
            })?;
        if root.len() != header.algorithm.digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root digest length does not match the hash algorithm",
            ));
        }

        Self {
            header: *header,
            data,
            hash,
            hash_start: 0,
            root,
            corruption_policy: CorruptionPolicy::Error,
            io_error_policy: IoErrorPolicy::Error,
            ignore_zero_blocks: false,
            check_at_most_once: false,
            try_verify_in_tasklet: false,
            root_hash_sig_key_desc: None,
            data_sectors,
            tree_size,
        }
        .hash_start(hash_start)
    }

    /// Changes the tree offset in hash-sized blocks.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the resulting hash extent
    /// overflows.
    pub fn hash_start(mut self, value: u64) -> io::Result<Self> {
        let size = u128::from(self.header.hash.bytes().get());
        u128::from(value)
            .checked_mul(size)
            .and_then(|start| start.checked_add(self.tree_size))
            .filter(|end| end / 512 <= u128::from(u64::MAX))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "verity hash extent overflows")
            })?;
        self.hash_start = value;
        Ok(self)
    }

    /// Selects corruption handling.
    #[must_use]
    pub const fn corruption_policy(mut self, value: CorruptionPolicy) -> Self {
        self.corruption_policy = value;
        self
    }

    /// Selects I/O-error handling.
    #[must_use]
    pub const fn io_error_policy(mut self, value: IoErrorPolicy) -> Self {
        self.io_error_policy = value;
        self
    }

    /// Selects authenticated zero-block handling.
    #[must_use]
    pub const fn ignore_zero_blocks(mut self, value: bool) -> Self {
        self.ignore_zero_blocks = value;
        self
    }

    /// Selects first-read-only verification.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the data extent contains
    /// more blocks than the kernel can track for this mode.
    pub fn check_at_most_once(mut self, value: bool) -> io::Result<Self> {
        if value && self.header.data.count.get() > i32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many data blocks for check_at_most_once",
            ));
        }
        self.check_at_most_once = value;
        Ok(self)
    }

    /// Requests kernel bottom-half verification.
    #[must_use]
    pub const fn try_verify_in_tasklet(mut self, value: bool) -> Self {
        self.try_verify_in_tasklet = value;
        self
    }

    /// Selects a kernel root-signature key.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an empty description or
    /// one containing a NUL byte.
    pub fn root_hash_sig_key_desc(mut self, value: impl Into<String>) -> io::Result<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid signature key description",
            ));
        }
        self.root_hash_sig_key_desc = Some(value);
        Ok(self)
    }

    /// Converts this valid configuration into an owned target description.
    pub fn build(self) -> VerityTarget {
        VerityTarget {
            hash_type: self.header.hash_type,
            data: self.data,
            hash: self.hash,
            geometry: self.header.data,
            block: self.header.hash,
            hash_start: self.hash_start,
            algorithm: self.header.algorithm,
            salt: self.header.salt,
            corruption_policy: self.corruption_policy,
            io_error_policy: self.io_error_policy,
            ignore_zero_blocks: self.ignore_zero_blocks,
            check_at_most_once: self.check_at_most_once,
            try_verify_in_tasklet: self.try_verify_in_tasklet,
            signature: self.root_hash_sig_key_desc,
            root: self.root,
            data_sectors: self.data_sectors,
        }
    }
}
