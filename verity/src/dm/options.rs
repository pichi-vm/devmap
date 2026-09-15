// SPDX-License-Identifier: Apache-2.0

use devmap_core::parse::DevId;
use std::io;
use std::num::NonZeroU64;

/// Action when a block does not match its expected hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CorruptionPolicy {
    /// Fail the read.
    #[default]
    Error,
    /// Log corruption and allow the read.
    Ignore,
    /// Restart the machine.
    Restart,
    /// Panic the kernel.
    Panic,
}

/// Action when the backing storage reports an I/O error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoErrorPolicy {
    /// Return the I/O error.
    #[default]
    Error,
    /// Restart the machine.
    Restart,
    /// Panic the kernel.
    Panic,
}

/// Forward-error-correction storage and Reed-Solomon parameters.
///
/// Counts and offsets use the target's data-block size. This describes existing
/// parity storage; it does not generate parity. Kernel support is checked on load.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fec {
    pub(super) device: DevId,
    pub(super) blocks: NonZeroU64,
    pub(super) roots: u8,
    pub(super) start: u64,
}

impl Fec {
    /// Describes parity storage covering `blocks` data/hash/metadata blocks.
    ///
    /// `roots` is the number of parity bytes per 255-byte codeword.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` unless `roots` is between 2 and 24 inclusive.
    pub fn new(device: DevId, blocks: NonZeroU64, roots: u8) -> io::Result<Self> {
        if !(2..=24).contains(&roots) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fec_roots must be between 2 and 24",
            ));
        }
        Ok(Self {
            device,
            blocks,
            roots,
            start: 0,
        })
    }
    /// Sets the parity offset in data-sized blocks from its device's start.
    #[must_use]
    pub const fn start(mut self, blocks: u64) -> Self {
        self.start = blocks;
        self
    }
    /// Returns the parity device.
    pub const fn device(&self) -> DevId {
        self.device
    }
    /// Returns the number of blocks covered by parity.
    pub const fn blocks(&self) -> NonZeroU64 {
        self.blocks
    }
    /// Returns the parity bytes per codeword.
    pub const fn roots(&self) -> u8 {
        self.roots
    }
    /// Returns the parity offset in data-sized blocks.
    pub const fn start_block(&self) -> u64 {
        self.start
    }
}
