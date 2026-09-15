// SPDX-License-Identifier: Apache-2.0

//! Complete Linux verity target parameters, independent of userspace hashing.
//!
//! Construct [`Builder`](crate::dm::Builder) directly for a headerless tree,
//! or convert an opened [`Header`] with [`Builder::from`](crate::dm::Builder::from).
//! A header supplies format parameters, not the trusted root digest or device
//! IDs; pass those to [`Builder::build`](crate::dm::Builder::build).
//! Use a backend table builder to choose row start/length and access mode, or
//! [`Target::add_full`](crate::dm::Target::add_full) for a full-size, read-only
//! row. Loading and resuming remain separate backend operations. This module
//! performs no device-mapper ioctls and is available without hashing dependencies.

use crate::{HashType, Header};
use devmap_core::{DevId, ParseError, Target as DmTarget};
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
/// The kernel checks actual device geometry and availability of optional features.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    data_dev: DevId,
    hash_dev: DevId,
    data_blocks: NonZeroU64,
    root: Vec<u8>,
    settings: builder::Settings,
    data_sectors: u64,
}

impl Target {
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

    /// Adds a full-size read-only row at sector zero to an empty table builder.
    ///
    /// Does not load or resume the device. Use the backend's ordinary `add`
    /// operation instead when explicitly selecting a shorter row.
    ///
    /// # Errors
    ///
    /// Returns errors from the supplied table builder.
    pub fn add_full<B: devmap_core::TableBuilder>(self, builder: B) -> io::Result<B> {
        let length = self.data_sectors;
        builder.read_only().add(0, length, self)
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

impl DmTarget for Target {
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
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let corrupted = match fields.next().ok_or(ParseError)? {
            "C" => true,
            "V" => false,
            _ => return Err(ParseError),
        };
        let fec_corrected = match fields.next().ok_or(ParseError)? {
            "-" => None,
            n => Some(n.parse()?),
        };
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Self {
            corrupted,
            fec_corrected,
        })
    }
}
