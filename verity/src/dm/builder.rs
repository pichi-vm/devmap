// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use super::{CorruptionPolicy, Fec, IoErrorPolicy, Target};
use crate::{Algorithm, HashType, Header};
use devmap_core::DevId;

const BLOCK: NonZeroU32 = NonZeroU32::new(4096).unwrap();

/// Configures a kernel verity target without initializing a hash implementation.
///
/// Defaults are format 1, SHA-256, 4096-byte data/hash blocks, tree start
/// block 1, no salt, and ordinary error handling. Use [`From<&Header>`]
/// to copy all format fields from an opened hash device instead.
#[derive(Debug, Clone)]
#[must_use]
pub struct Builder {
    pub(super) data_blocks: NonZeroU64,
    pub(super) settings: Settings,
    header_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct Settings {
    pub hash_type: HashType,
    pub data_block_size: NonZeroU32,
    pub hash_block_size: NonZeroU32,
    pub hash_start: u64,
    pub algorithm: String,
    pub salt: Vec<u8>,
    pub corruption: CorruptionPolicy,
    pub io_error: IoErrorPolicy,
    pub ignore_zero: bool,
    pub at_most_once: bool,
    pub tasklet: bool,
    pub fec: Option<Fec>,
    pub signature: Option<String>,
}

impl Builder {
    /// Configures a target protecting `data_blocks` blocks.
    pub fn new(data_blocks: NonZeroU64) -> Self {
        Self {
            data_blocks,
            header_offset: None,
            settings: Settings {
                hash_type: HashType::Normal,
                data_block_size: BLOCK,
                hash_block_size: BLOCK,
                hash_start: 1,
                algorithm: "sha256".into(),
                salt: Vec::new(),
                corruption: CorruptionPolicy::Error,
                io_error: IoErrorPolicy::Error,
                ignore_zero: false,
                at_most_once: false,
                tasklet: false,
                fec: None,
                signature: None,
            },
        }
    }

    /// Selects hash format 0 or 1.
    pub const fn hash_type(mut self, value: HashType) -> Self {
        self.settings.hash_type = value;
        self
    }

    fn block_size(bytes: u32) -> io::Result<NonZeroU32> {
        if bytes < 512 || !bytes.is_power_of_two() || bytes > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verity block size",
            ));
        }
        NonZeroU32::new(bytes).ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// Sets the data-block size in bytes.
    ///
    /// # Errors
    ///
    /// Rejects sizes below 512 or non-powers of two. Actual device alignment
    /// and the running kernel's page-size limit are checked on table load.
    pub fn data_block_size(mut self, bytes: u32) -> io::Result<Self> {
        self.settings.data_block_size = Self::block_size(bytes)?;
        Ok(self)
    }

    /// Sets the hash-block size in bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid block sizes and incompatible previously supplied header offsets.
    pub fn hash_block_size(mut self, bytes: u32) -> io::Result<Self> {
        let size = Self::block_size(bytes)?;
        if let Some(offset) = self.header_offset {
            self.settings.hash_start = Self::tree_after_header(offset, size)?;
        }
        self.settings.hash_block_size = size;
        Ok(self)
    }

    /// Sets the tree's starting block, relative to the hash device.
    ///
    /// Zero supports trees without a preceding superblock.
    pub const fn hash_start_block(mut self, block: u64) -> Self {
        self.settings.hash_start = block;
        self.header_offset = None;
        self
    }

    fn tree_after_header(offset: u64, size: NonZeroU32) -> io::Result<u64> {
        let size = u64::from(size.get());
        if offset % size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hash header offset is not block aligned",
            ));
        }
        (offset / size)
            .checked_add(1)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// Places the header at a byte offset in the actual Linux hash device.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for misalignment or an overflowing tree start.
    pub fn header_offset_bytes(mut self, offset: u64) -> io::Result<Self> {
        self.settings.hash_start = Self::tree_after_header(offset, self.settings.hash_block_size)?;
        self.header_offset = Some(offset);
        Ok(self)
    }

    /// Selects any nonempty kernel algorithm name, including unimplemented families.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for NUL or whitespace in the name.
    pub fn algorithm(mut self, name: impl AsRef<str>) -> io::Result<Self> {
        let name = name.as_ref();
        if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c == '\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid kernel hash algorithm name",
            ));
        }
        self.settings.algorithm = name.into();
        Ok(self)
    }

    /// Sets raw salt bytes. Kernel tables are not limited by the header's 256-byte field.
    pub fn salt(mut self, salt: &[u8]) -> Self {
        self.settings.salt = salt.into();
        self
    }
    /// Selects corruption handling.
    pub const fn corruption_policy(mut self, value: CorruptionPolicy) -> Self {
        self.settings.corruption = value;
        self
    }
    /// Selects I/O-error handling independently of corruption handling.
    pub const fn io_error_policy(mut self, value: IoErrorPolicy) -> Self {
        self.settings.io_error = value;
        self
    }
    /// Returns zeroes for blocks whose expected digest represents a zero block.
    pub const fn ignore_zero_blocks(mut self, value: bool) -> Self {
        self.settings.ignore_zero = value;
        self
    }
    /// Checks data only on its first read, weakening detection of online changes.
    pub const fn check_at_most_once(mut self, value: bool) -> Self {
        self.settings.at_most_once = value;
        self
    }
    /// Requests verification in bottom-half context when the kernel permits it.
    pub const fn try_verify_in_tasklet(mut self, value: bool) -> Self {
        self.settings.tasklet = value;
        self
    }
    /// Enables recovery using existing parity storage.
    pub fn fec(mut self, value: Fec) -> Self {
        self.settings.fec = Some(value);
        self
    }
    /// Supplies the kernel user-key description holding a root-hash signature.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an empty description or embedded NUL.
    pub fn root_hash_sig_key_desc(mut self, value: impl Into<String>) -> io::Result<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid signature key description",
            ));
        }
        self.settings.signature = Some(value);
        Ok(self)
    }

    /// Binds device identities and an externally trusted root digest.
    ///
    /// Performs no device I/O. Device capacity and kernel feature availability
    /// are checked when the target is loaded.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for arithmetic overflow, a wrong known digest
    /// length, an empty digest, or incompatible FEC settings.
    pub fn build(self, data_dev: DevId, hash_dev: DevId, root: &[u8]) -> io::Result<Target> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        let data_sectors = self
            .data_blocks
            .get()
            .checked_mul(u64::from(self.settings.data_block_size.get() / 512))
            .ok_or_else(|| invalid("verity data extent overflows"))?;
        self.settings
            .hash_start
            .checked_mul(u64::from(self.settings.hash_block_size.get() / 512))
            .ok_or_else(|| invalid("verity hash start overflows"))?;
        let known = self.settings.algorithm.parse::<Algorithm>().ok();
        if root.is_empty() || known.is_some_and(|a| a.digest_size() != root.len()) {
            return Err(invalid(
                "root digest length does not match the hash algorithm",
            ));
        }
        let capacity = self.settings.hash_block_size.get() as usize / root.len();
        if capacity < 2 {
            return Err(invalid("hash block cannot hold two digests"));
        }
        let fanout = 1u64 << capacity.ilog2();
        let mut blocks = self.data_blocks.get();
        let mut tree_blocks = 0u64;
        while blocks > 1 {
            blocks = blocks.div_ceil(fanout);
            tree_blocks = tree_blocks
                .checked_add(blocks)
                .ok_or_else(|| invalid("verity tree extent overflows"))?;
        }
        self.settings
            .hash_start
            .checked_add(tree_blocks)
            .and_then(|end| end.checked_mul(u64::from(self.settings.hash_block_size.get() / 512)))
            .ok_or_else(|| invalid("verity hash extent overflows"))?;
        if self.settings.at_most_once && self.data_blocks.get() > i32::MAX as u64 {
            return Err(invalid("too many data blocks for check_at_most_once"));
        }
        if let Some(fec) = &self.settings.fec {
            if self.settings.data_block_size != self.settings.hash_block_size {
                return Err(invalid("FEC requires equal data and hash block sizes"));
            }
            let protected = self
                .data_blocks
                .get()
                .checked_add(tree_blocks)
                .ok_or_else(|| invalid("FEC extent overflows"))?;
            if fec.blocks.get() < protected {
                return Err(invalid("fec_blocks does not cover data and hashes"));
            }
            let parity = fec
                .blocks
                .get()
                .div_ceil(255 - u64::from(fec.roots))
                .checked_mul(u64::from(fec.roots))
                .and_then(|blocks| fec.start.checked_add(blocks))
                .and_then(|blocks| {
                    blocks.checked_mul(u64::from(self.settings.data_block_size.get() / 512))
                });
            if parity.is_none() {
                return Err(invalid("FEC parity extent overflows"));
            }
        }
        Ok(Target {
            data_dev,
            hash_dev,
            data_blocks: self.data_blocks,
            root: root.into(),
            settings: self.settings,
            data_sectors,
        })
    }
}

impl From<&Header> for Builder {
    fn from(header: &Header) -> Self {
        let mut builder = Self::new(header.data_blocks());
        builder.settings.hash_type = header.hash_type();
        builder.settings.data_block_size = header.data_block_size();
        builder.settings.hash_block_size = header.hash_block_size();
        builder.settings.algorithm = header.algorithm().to_string();
        builder.settings.salt = header.salt().into();
        builder.header_offset = Some(0);
        builder
    }
}
