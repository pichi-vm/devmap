// SPDX-License-Identifier: Apache-2.0

//! Linux verity target descriptions, available without hashing dependencies.
//!
//! Configure a [`Builder`] directly or from a [`Header`]. Pass the resulting
//! [`VerityTarget`] to a backend such as `devmap-linux` for activation.

use crate::{HashType, Header};
use devmap_core::Target;
use devmap_core::parse::{DevId, Error};
use std::{
    fmt, io,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
};

mod builder;
mod codec;
mod options;
pub use builder::Builder;
pub use options::{CorruptionPolicy, Fec, IoErrorPolicy};

/// All parameters of a kernel dm-verity target.
///
/// Devices must contain the described data and tree and the root must be
/// obtained from an independently trusted source. Construct with [`Builder`].
/// Load in a read-only table; [`data_sectors`](Self::data_sectors) gives the
/// full row length.
/// The kernel checks actual device geometry and availability of optional features.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerityTarget {
    data_dev: DevId,
    hash_dev: DevId,
    data_blocks: NonZeroU64,
    root: Vec<u8>,
    settings: builder::Settings,
    data_sectors: u64,
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
    /// Returns the on-disk hashing convention.
    pub const fn hash_type(&self) -> HashType {
        self.settings.hash_type
    }
    /// Returns the data-block size in bytes.
    pub const fn data_block_size(&self) -> NonZeroU32 {
        self.settings.data_block_size
    }
    /// Returns the hash-block size in bytes.
    pub const fn hash_block_size(&self) -> NonZeroU32 {
        self.settings.hash_block_size
    }
    /// Returns the number of blocks covered by the tree.
    pub const fn data_blocks(&self) -> NonZeroU64 {
        self.data_blocks
    }
    /// Returns the tree offset in hash-sized blocks.
    pub const fn hash_start_block(&self) -> u64 {
        self.settings.hash_start
    }
    /// Returns the kernel algorithm name.
    pub fn algorithm(&self) -> &str {
        &self.settings.algorithm
    }
    /// Returns the externally supplied root digest.
    pub fn root_digest(&self) -> &[u8] {
        &self.root
    }
    /// Returns the salt bytes.
    pub fn salt(&self) -> &[u8] {
        &self.settings.salt
    }
    /// Returns the corruption action.
    pub const fn corruption_policy(&self) -> CorruptionPolicy {
        self.settings.corruption
    }
    /// Returns the I/O-error action.
    pub const fn io_error_policy(&self) -> IoErrorPolicy {
        self.settings.io_error
    }
    /// Returns whether expected zero blocks bypass verification.
    pub const fn ignore_zero_blocks(&self) -> bool {
        self.settings.ignore_zero
    }
    /// Returns whether data is verified only on first access.
    pub const fn check_at_most_once(&self) -> bool {
        self.settings.at_most_once
    }
    /// Returns whether bottom-half verification is requested.
    pub const fn try_verify_in_tasklet(&self) -> bool {
        self.settings.tasklet
    }
    /// Returns the optional error-correction configuration.
    pub const fn fec(&self) -> Option<&Fec> {
        self.settings.fec.as_ref()
    }
    /// Returns the optional signature-key description.
    pub fn root_hash_sig_key_desc(&self) -> Option<&str> {
        self.settings.signature.as_deref()
    }
    /// Returns the maximum exposed length in 512-byte sectors.
    ///
    /// A backend row may expose a shorter aligned prefix.
    pub const fn data_sectors(&self) -> u64 {
        self.data_sectors
    }

    /// Constructs portable header metadata using the supplied UUID.
    ///
    /// This projects only header fields; device identities, tree location,
    /// root digest and Linux-only options remain on this target. It performs
    /// no I/O and does not imply the backing storage actually contains a header.
    ///
    /// # Errors
    ///
    /// Returns an error if an algorithm, salt, block size or extent cannot
    /// be represented by the portable header format.
    pub fn to_header(&self, uuid: [u8; 16]) -> io::Result<Header> {
        let algorithm = self
            .algorithm()
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::Unsupported, error))?;
        Header::from_parts(
            uuid,
            self.hash_type(),
            algorithm,
            self.data_block_size(),
            self.hash_block_size(),
            self.data_blocks(),
            self.salt(),
        )
    }
}

impl Target for VerityTarget {
    const NAME: &'static str = "verity";
    type Table = Self;
    type Info = Info;
}

/// Runtime corruption status and number of FEC-corrected blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Whether any hash mismatch has occurred.
    pub corrupted: bool,
    /// Corrected blocks, or `None` if FEC is disabled.
    pub fec_corrected: Option<u64>,
}
impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", if self.corrupted { 'C' } else { 'V' })?;
        match self.fec_corrected {
            Some(count) => count.fmt(f),
            None => f.write_str("-"),
        }
    }
}
impl FromStr for Info {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let corrupted = match fields.next().ok_or(Error)? {
            "C" => true,
            "V" => false,
            _ => return Err(Error),
        };
        let fec_corrected = match fields.next().ok_or(Error)? {
            "-" => None,
            n => Some(n.parse()?),
        };
        if fields.next().is_some() {
            return Err(Error);
        }
        Ok(Self {
            corrupted,
            fec_corrected,
        })
    }
}
