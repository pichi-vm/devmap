// SPDX-License-Identifier: Apache-2.0

use super::{CorruptionPolicy, Fec, Info, IoErrorPolicy};
use crate::Parameters;
use devmap_core::Target;
use devmap_core::parse::DevId;
use std::io;

/// All parameters of a kernel dm-verity target.
///
/// Devices must contain the described data and tree and the root must be
/// obtained from an independently trusted source. Construct with [`Parameters::target`].
/// Load in a read-only table; [`data_sectors`](Self::data_sectors) gives the
/// full row length.
/// The kernel checks actual device geometry and availability of optional features.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerityTarget {
    pub(super) data_dev: DevId,
    pub(super) hash_dev: DevId,
    pub(super) parameters: Parameters,
    pub(super) root: Vec<u8>,
    pub(super) hash_start: u64,
    pub(super) corruption: CorruptionPolicy,
    pub(super) io_error: IoErrorPolicy,
    pub(super) ignore_zero: bool,
    pub(super) at_most_once: bool,
    pub(super) tasklet: bool,
    pub(super) fec: Option<Fec>,
    pub(super) signature: Option<String>,
}

impl VerityTarget {
    /// Returns the data device.
    pub const fn data_dev(&self) -> DevId {
        self.data_dev
    }
    /// Returns the hash device.
    pub const fn hash_dev(&self) -> DevId {
        self.hash_dev
    }
    /// Borrows the shared hashing parameters.
    pub const fn parameters(&self) -> &Parameters {
        &self.parameters
    }
    /// Returns the tree offset in hash-sized blocks.
    pub const fn hash_start_block(&self) -> u64 {
        self.hash_start
    }
    /// Returns the externally supplied root digest.
    pub fn root_digest(&self) -> &[u8] {
        &self.root
    }
    /// Returns the corruption action.
    pub const fn corruption_policy(&self) -> CorruptionPolicy {
        self.corruption
    }
    /// Returns the I/O-error action.
    pub const fn io_error_policy(&self) -> IoErrorPolicy {
        self.io_error
    }
    /// Returns whether expected zero blocks bypass verification.
    pub const fn ignore_zero_blocks(&self) -> bool {
        self.ignore_zero
    }
    /// Returns whether data is verified only on first access.
    pub const fn check_at_most_once(&self) -> bool {
        self.at_most_once
    }
    /// Returns whether bottom-half verification is requested.
    pub const fn try_verify_in_tasklet(&self) -> bool {
        self.tasklet
    }
    /// Returns the optional error-correction configuration.
    pub const fn fec(&self) -> Option<&Fec> {
        self.fec.as_ref()
    }
    /// Returns the optional signature-key description.
    pub fn root_hash_sig_key_desc(&self) -> Option<&str> {
        self.signature.as_deref()
    }
    /// Returns the maximum exposed length in 512-byte sectors.
    ///
    /// A backend row may expose a shorter aligned prefix.
    pub const fn data_sectors(&self) -> u64 {
        (self.parameters.layout.data_size / 512) as u64
    }
}

impl Target for VerityTarget {
    const NAME: &'static str = "verity";
    type Table = Self;
    type Info = Info;
}

impl Parameters {
    /// Binds device IDs and a trusted root digest into a Linux target.
    ///
    /// The tree starts at hash block 1, after a header. Change its location
    /// with [`VerityTarget::with_hash_start_block`] or
    /// [`VerityTarget::with_header_offset_bytes`]. Performs no I/O.
    /// Device capacity and kernel feature availability are checked on table load.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for a root digest of the wrong length or an
    /// overflowing hash extent.
    ///
    /// ```
    /// use std::num::NonZeroU64;
    /// use devmap_core::parse::DevId;
    /// use devmap_verity::Parameters;
    ///
    /// # fn target(root: &[u8]) -> std::io::Result<()> {
    /// let target = Parameters::builder()
    ///     .build(NonZeroU64::new(128).unwrap())?
    ///     .target(DevId::new(7, 0).unwrap(), DevId::new(7, 1).unwrap(), root)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn target(
        &self,
        data_dev: DevId,
        hash_dev: DevId,
        root: &[u8],
    ) -> io::Result<VerityTarget> {
        if root.len() != self.algorithm().digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root digest length does not match the hash algorithm",
            ));
        }
        VerityTarget {
            parameters: self.clone(),
            data_dev,
            hash_dev,
            root: root.into(),
            hash_start: 1,
            corruption: CorruptionPolicy::Error,
            io_error: IoErrorPolicy::Error,
            ignore_zero: false,
            at_most_once: false,
            tasklet: false,
            fec: None,
            signature: None,
        }
        .with_hash_start_block(1)
    }
}

impl VerityTarget {
    /// Sets the tree's starting block relative to the Linux hash device.
    ///
    /// Zero supports a tree without a preceding header.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the hash extent overflows.
    pub fn with_hash_start_block(mut self, block: u64) -> io::Result<Self> {
        let size = u64::from(self.parameters.hash_block_size().get());
        let end = u128::from(block) * u128::from(size) + self.parameters.layout.tree_size;
        if end / 512 > u128::from(u64::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "verity hash extent overflows",
            ));
        }
        self.hash_start = block;
        Ok(self)
    }

    /// Places the header at a byte offset in the complete Linux hash device.
    ///
    /// Supply this offset when the header was opened through a zero-based region.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for misalignment or an overflowing hash extent.
    pub fn with_header_offset_bytes(self, offset: u64) -> io::Result<Self> {
        let size = u64::from(self.parameters.hash_block_size().get());
        if offset % size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hash header offset is not block aligned",
            ));
        }
        self.with_hash_start_block(offset / size + 1)
    }

    /// Selects corruption handling.
    #[must_use]
    pub const fn with_corruption_policy(mut self, value: CorruptionPolicy) -> Self {
        self.corruption = value;
        self
    }

    /// Selects I/O-error handling independently of corruption handling.
    #[must_use]
    pub const fn with_io_error_policy(mut self, value: IoErrorPolicy) -> Self {
        self.io_error = value;
        self
    }

    /// Returns zeroes for blocks whose expected digest represents a zero block.
    #[must_use]
    pub const fn with_ignore_zero_blocks(mut self, value: bool) -> Self {
        self.ignore_zero = value;
        self
    }

    /// Checks data only on its first read, weakening detection of online changes.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if enabled for more than `i32::MAX` data blocks.
    pub fn with_check_at_most_once(mut self, value: bool) -> io::Result<Self> {
        if value && self.parameters.data_blocks().get() > i32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many data blocks for check_at_most_once",
            ));
        }
        self.at_most_once = value;
        Ok(self)
    }

    /// Requests verification in bottom-half context when the kernel permits it.
    #[must_use]
    pub const fn with_try_verify_in_tasklet(mut self, value: bool) -> Self {
        self.tasklet = value;
        self
    }

    /// Enables recovery using existing parity storage.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for unequal data/hash block sizes, insufficient
    /// protected blocks, or an overflowing parity extent.
    pub fn with_fec(mut self, fec: Fec) -> io::Result<Self> {
        let parameters = &self.parameters;
        if parameters.data_block_size() != parameters.hash_block_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FEC requires equal data and hash block sizes",
            ));
        }
        let size = u64::from(parameters.hash_block_size().get());
        let protected = parameters
            .data_blocks()
            .get()
            .checked_add((parameters.layout.tree_size / u128::from(size)) as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "FEC extent overflows"))?;
        if fec.blocks.get() < protected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fec_blocks does not cover data and hashes",
            ));
        }
        fec.blocks
            .get()
            .div_ceil(255 - u64::from(fec.roots))
            .checked_mul(u64::from(fec.roots))
            .and_then(|blocks| fec.start.checked_add(blocks))
            .and_then(|blocks| blocks.checked_mul(size / 512))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "FEC parity extent overflows")
            })?;
        self.fec = Some(fec);
        Ok(self)
    }

    /// Supplies the kernel user-key description holding a root-hash signature.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an empty description or embedded NUL.
    pub fn with_root_hash_sig_key_desc(mut self, value: impl Into<String>) -> io::Result<Self> {
        let value = value.into();
        if value.is_empty() || value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid signature key description",
            ));
        }
        self.signature = Some(value);
        Ok(self)
    }
}
