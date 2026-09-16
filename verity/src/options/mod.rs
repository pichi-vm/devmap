// SPDX-License-Identifier: Apache-2.0

use crate::layout::Layout;
use devmap_core::BlockSize;
use std::io;

mod fec;
mod key_description;
mod policy;
pub use fec::Fec;
pub use key_description::KeyDescription;
pub use policy::{CorruptionPolicy, IoErrorPolicy};

/// Editable verification and Linux activation settings.
///
/// Defaults to strict verification, tree start at block 1, and no extra
/// features. Consumers validate combinations against their scheme and shape.
/// Userspace opening rejects kernel-only settings and FEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Options<'a> {
    /// Tree start in hash-sized blocks of the Linux hash device.
    pub hash_start_block: u64,
    /// Response to an authentication failure.
    pub corruption_policy: CorruptionPolicy,
    /// Response to an I/O failure.
    pub io_error_policy: IoErrorPolicy,
    /// Return zeroes without reading data whose authenticated digest is a zero block.
    pub ignore_zero_blocks: bool,
    /// Verify each data block only once; later reads can miss changes.
    pub check_at_most_once: bool,
    /// Request kernel verification in bottom-half context.
    pub try_verify_in_tasklet: bool,
    /// Existing kernel parity storage; userspace recovery is not supported.
    pub fec: Option<Fec>,
    /// Kernel user-key description holding a root-hash signature.
    pub root_hash_sig_key_desc: Option<KeyDescription<'a>>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            hash_start_block: 1,
            corruption_policy: CorruptionPolicy::Error,
            io_error_policy: IoErrorPolicy::Error,
            ignore_zero_blocks: false,
            check_at_most_once: false,
            try_verify_in_tasklet: false,
            fec: None,
            root_hash_sig_key_desc: None,
        }
    }
}

impl<'a> Options<'a> {
    /// Selects the tree start in hash-sized blocks; zero supports headerless trees.
    #[must_use]
    pub const fn with_hash_start_block(mut self, value: u64) -> Self {
        self.hash_start_block = value;
        self
    }
    /// Selects corruption handling.
    #[must_use]
    pub const fn with_corruption_policy(mut self, value: CorruptionPolicy) -> Self {
        self.corruption_policy = value;
        self
    }
    /// Selects I/O-error handling.
    #[must_use]
    pub const fn with_io_error_policy(mut self, value: IoErrorPolicy) -> Self {
        self.io_error_policy = value;
        self
    }
    /// Selects authenticated zero-block handling.
    #[must_use]
    pub const fn with_ignore_zero_blocks(mut self, value: bool) -> Self {
        self.ignore_zero_blocks = value;
        self
    }
    /// Selects first-read-only verification.
    ///
    /// Userspace allocates one tracking bit per data block. Both consumers
    /// reject more than `i32::MAX` blocks when this option is enabled.
    #[must_use]
    pub const fn with_check_at_most_once(mut self, value: bool) -> Self {
        self.check_at_most_once = value;
        self
    }
    /// Requests kernel bottom-half verification.
    #[must_use]
    pub const fn with_try_verify_in_tasklet(mut self, value: bool) -> Self {
        self.try_verify_in_tasklet = value;
        self
    }
    /// Selects existing kernel parity storage.
    #[must_use]
    pub const fn with_fec(mut self, value: Fec) -> Self {
        self.fec = Some(value);
        self
    }
    /// Selects a kernel root-signature key.
    #[must_use]
    pub const fn with_root_hash_sig_key_desc(mut self, value: KeyDescription<'a>) -> Self {
        self.root_hash_sig_key_desc = Some(value);
        self
    }

    /// Converts an embedded header's byte offset to a tree start.
    ///
    /// Uses the supplied hash-block size; later geometry changes do not
    /// recompute the offset.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the offset is not hash-block aligned.
    pub fn with_header_offset_bytes(self, offset: u64, block_size: BlockSize) -> io::Result<Self> {
        let size = u64::from(u32::from(block_size));
        if offset % size != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hash header offset is not block aligned",
            ));
        }
        Ok(self.with_hash_start_block(offset / size + 1))
    }

    pub(crate) fn validate(&self, layout: &Layout) -> io::Result<()> {
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
        let size = u64::from(u32::from(layout.shape.hash_block_size));
        let end = u128::from(self.hash_start_block) * u128::from(size) + layout.tree_size;
        if end / 512 > u128::from(u64::MAX) {
            return Err(invalid("verity hash extent overflows"));
        }
        if self.check_at_most_once && layout.shape.data_blocks.get() > i32::MAX as u64 {
            return Err(invalid("too many data blocks for check_at_most_once"));
        }
        if let Some(fec) = self.fec {
            if layout.shape.data_block_size != layout.shape.hash_block_size {
                return Err(invalid("FEC requires equal data and hash block sizes"));
            }
            let protected = layout
                .shape
                .data_blocks
                .get()
                .checked_add((layout.tree_size / u128::from(size)) as u64)
                .ok_or_else(|| invalid("FEC extent overflows"))?;
            if fec.blocks.get() < protected {
                return Err(invalid("fec_blocks does not cover data and hashes"));
            }
            fec.blocks
                .get()
                .div_ceil(255 - u64::from(fec.roots))
                .checked_mul(u64::from(fec.roots))
                .and_then(|blocks| fec.start.checked_add(blocks))
                .and_then(|blocks| blocks.checked_mul(size / 512))
                .ok_or_else(|| invalid("FEC parity extent overflows"))?;
        }
        Ok(())
    }

    pub(crate) fn without_signature(self) -> Options<'static> {
        Options {
            root_hash_sig_key_desc: None,
            ..self
        }
    }
}
