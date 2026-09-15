// SPDX-License-Identifier: Apache-2.0

//! The `thin-pool` target: a pool of storage backing one or more
//! thin-provisioned volumes.

use std::fmt;
use std::io;
use std::str::FromStr;

use devmap_core::{DevId, TargetEndpoint};
use devmap_core::{Fraction, ParseError, Target as DmTarget};

/// A thin-provisioning pool backing zero or more `Thin` devices.
/// Provisioning (`create_thin`/`create_snap`/`delete`) is
/// message-driven — see [`devmap_core::TargetEndpoint::message`]. Build via
/// [`Target::builder`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)] // mirrors dm-thin's five kernel feature flags
pub struct Target {
    metadata: DevId,
    data: DevId,
    data_block_size_sectors: u64,
    low_water_mark_blocks: u64,
    skip_block_zeroing: bool,
    ignore_discard: bool,
    no_discard_passdown: bool,
    read_only: bool,
    error_if_no_space: bool,
}
impl Target {
    /// Start building a [`Target`]. Feature flags default to off; set
    /// the ones you need on the returned builder, then `.build()`.
    #[must_use]
    pub fn builder(
        metadata: DevId,
        data: DevId,
        data_block_size_sectors: u64,
        low_water_mark_blocks: u64,
    ) -> Builder {
        Builder {
            metadata,
            data,
            data_block_size_sectors,
            low_water_mark_blocks,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: false,
            read_only: false,
            error_if_no_space: false,
        }
    }

    /// The metadata device.
    #[must_use]
    pub fn metadata(&self) -> DevId {
        self.metadata
    }
    /// The data device.
    #[must_use]
    pub fn data(&self) -> DevId {
        self.data
    }
    /// The data block size in sectors.
    #[must_use]
    pub fn data_block_size_sectors(&self) -> u64 {
        self.data_block_size_sectors
    }
    /// The low-water-mark, in blocks.
    #[must_use]
    pub fn low_water_mark_blocks(&self) -> u64 {
        self.low_water_mark_blocks
    }
    /// Whether newly-provisioned blocks are left unzeroed.
    #[must_use]
    pub fn skip_block_zeroing(&self) -> bool {
        self.skip_block_zeroing
    }
    /// Whether discard support is disabled.
    #[must_use]
    pub fn ignore_discard(&self) -> bool {
        self.ignore_discard
    }
    /// Whether discards are not passed down to the data device.
    #[must_use]
    pub fn no_discard_passdown(&self) -> bool {
        self.no_discard_passdown
    }
    /// Whether the pool is loaded read-only.
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    /// Whether I/O errors (rather than queues) once out of space.
    #[must_use]
    pub fn error_if_no_space(&self) -> bool {
        self.error_if_no_space
    }
}
impl DmTarget for Target {
    const NAME: &'static str = "thin-pool";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.metadata, self.data, self.data_block_size_sectors, self.low_water_mark_blocks
        )?;
        let flags: [(bool, &str); 5] = [
            (self.skip_block_zeroing, "skip_block_zeroing"),
            (self.ignore_discard, "ignore_discard"),
            (self.no_discard_passdown, "no_discard_passdown"),
            (self.read_only, "read_only"),
            (self.error_if_no_space, "error_if_no_space"),
        ];
        let count = flags.iter().filter(|(set, _)| *set).count();
        write!(f, " {count}")?;
        for (set, name) in flags {
            if set {
                write!(f, " {name}")?;
            }
        }
        Ok(())
    }
}
impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let mut pool = Target {
            metadata: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            data: fields.next().ok_or(ParseError)?.parse::<DevId>()?,
            data_block_size_sectors: fields.next().ok_or(ParseError)?.parse()?,
            low_water_mark_blocks: fields.next().ok_or(ParseError)?.parse()?,
            skip_block_zeroing: false,
            ignore_discard: false,
            no_discard_passdown: false,
            read_only: false,
            error_if_no_space: false,
        };
        // Every dm-thin feature is a bare flag, so the count is both a
        // token count and a feature count.
        let count: usize = fields.next().ok_or(ParseError)?.parse()?;
        for _ in 0..count {
            match fields.next().ok_or(ParseError)? {
                "skip_block_zeroing" => pool.skip_block_zeroing = true,
                "ignore_discard" => pool.ignore_discard = true,
                "no_discard_passdown" => pool.no_discard_passdown = true,
                "read_only" => pool.read_only = true,
                "error_if_no_space" => pool.error_if_no_space = true,
                _ => return Err(ParseError),
            }
        }
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(pool)
    }
}

/// Messages to a live [`Target`] — thin provisioning is driven entirely
/// through these, not through table reloads. Reach them via
/// a backend's typed target endpoint:
///
/// ```no_run
/// use devmap_thin_pool::dm::{Target, Commands as _};
/// fn create(pool: &impl devmap_core::TargetEndpoint<Target = Target>) -> std::io::Result<()> {
///     pool.create_thin(0)
/// }
/// ```
pub trait Commands: TargetEndpoint<Target = Target> {
    /// `create_thin <dev_id>` — provision a new thin volume with this id,
    /// ready to be mapped with a `Thin` table.
    fn create_thin(&self, dev_id: u32) -> io::Result<()> {
        self.message(&format!("create_thin {dev_id}")).map(drop)
    }

    /// `create_snap <dev_id> <origin_id>` — snapshot the thin volume
    /// `origin_id` into a new volume `dev_id`.
    fn create_snap(&self, dev_id: u32, origin_id: u32) -> io::Result<()> {
        self.message(&format!("create_snap {dev_id} {origin_id}"))
            .map(drop)
    }

    /// `delete <dev_id>` — delete a thin volume from the pool.
    fn delete(&self, dev_id: u32) -> io::Result<()> {
        self.message(&format!("delete {dev_id}")).map(drop)
    }

    /// `set_transaction_id <current> <new>` — advance the pool's
    /// transaction id, a compare-and-swap userspace uses to fence its own
    /// metadata operations.
    fn set_transaction_id(&self, current: u64, new: u64) -> io::Result<()> {
        self.message(&format!("set_transaction_id {current} {new}"))
            .map(drop)
    }

    /// `reserve_metadata_snap` — pin a metadata snapshot for offline
    /// inspection and return the block it was reserved at.
    ///
    /// # Errors
    ///
    /// The kernel's `io::Error`, or an error if the reply is missing or
    /// unparsable.
    fn reserve_metadata_snap(&self) -> io::Result<u64> {
        self.message("reserve_metadata_snap")?
            .and_then(|reply| reply.trim().parse().ok())
            .ok_or_else(|| io::Error::other("reserve_metadata_snap: no block in reply"))
    }

    /// `release_metadata_snap` — release the pinned metadata snapshot.
    fn release_metadata_snap(&self) -> io::Result<()> {
        self.message("release_metadata_snap").map(drop)
    }
}
impl<T: TargetEndpoint<Target = Target> + ?Sized> Commands for T {}

/// Builder for [`Target`] — see [`Target::builder`].
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // mirrors Target's five kernel feature flags
pub struct Builder {
    metadata: DevId,
    data: DevId,
    data_block_size_sectors: u64,
    low_water_mark_blocks: u64,
    skip_block_zeroing: bool,
    ignore_discard: bool,
    no_discard_passdown: bool,
    read_only: bool,
    error_if_no_space: bool,
}
impl Builder {
    /// Don't zero newly-provisioned blocks before use.
    #[must_use]
    pub fn skip_block_zeroing(mut self, on: bool) -> Self {
        self.skip_block_zeroing = on;
        self
    }
    /// Disable discard support.
    #[must_use]
    pub fn ignore_discard(mut self, on: bool) -> Self {
        self.ignore_discard = on;
        self
    }
    /// Don't pass discards down to the underlying data device.
    #[must_use]
    pub fn no_discard_passdown(mut self, on: bool) -> Self {
        self.no_discard_passdown = on;
        self
    }
    /// Load the pool read-only.
    #[must_use]
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Error (rather than queue) I/O once the pool is out of space.
    #[must_use]
    pub fn error_if_no_space(mut self, on: bool) -> Self {
        self.error_if_no_space = on;
        self
    }
    /// Finish building the [`Target`].
    #[must_use]
    pub fn build(self) -> Target {
        Target {
            metadata: self.metadata,
            data: self.data,
            data_block_size_sectors: self.data_block_size_sectors,
            low_water_mark_blocks: self.low_water_mark_blocks,
            skip_block_zeroing: self.skip_block_zeroing,
            ignore_discard: self.ignore_discard,
            no_discard_passdown: self.no_discard_passdown,
            read_only: self.read_only,
            error_if_no_space: self.error_if_no_space,
        }
    }
}

/// The access mode a [`Target`] is currently operating in. Distinct
/// from the `read_only` table flag: the kernel drops a pool to read-only
/// on its own when metadata fills or fails.
///
/// Encoded as `rw`, `ro`, or `out_of_data_space`; other tokens are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessMode {
    /// Reads and writes are served.
    ReadWrite,
    /// Writes are refused.
    ReadOnly,
    /// The data device is full, so writes that need a new block cannot be
    /// served.
    OutOfDataSpace,
}

impl FromStr for AccessMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rw" => Ok(Self::ReadWrite),
            "ro" => Ok(Self::ReadOnly),
            "out_of_data_space" => Ok(Self::OutOfDataSpace),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for AccessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
            Self::OutOfDataSpace => "out_of_data_space",
        })
    }
}

/// How a [`Target`] currently handles discards.
///
/// Encoded as `ignore_discard`, `discard_passdown`, or `no_discard_passdown`;
/// other tokens are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiscardMode {
    /// Discards are ignored.
    Ignore,
    /// Discards are passed down to the data device.
    Passdown,
    /// Discards are handled by the pool but not passed down.
    NoPassdown,
}

impl FromStr for DiscardMode {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ignore_discard" => Ok(Self::Ignore),
            "discard_passdown" => Ok(Self::Passdown),
            "no_discard_passdown" => Ok(Self::NoPassdown),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for DiscardMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ignore => "ignore_discard",
            Self::Passdown => "discard_passdown",
            Self::NoPassdown => "no_discard_passdown",
        })
    }
}

/// What a [`Target`] does with writes once the data device is full.
///
/// Encoded as `error_if_no_space` or `queue_if_no_space`; other tokens are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OutOfSpacePolicy {
    /// Fail the I/O.
    Error,
    /// Queue the I/O until space appears.
    Queue,
}

impl FromStr for OutOfSpacePolicy {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error_if_no_space" => Ok(Self::Error),
            "queue_if_no_space" => Ok(Self::Queue),
            _ => Err(ParseError),
        }
    }
}

impl fmt::Display for OutOfSpacePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Error => "error_if_no_space",
            Self::Queue => "queue_if_no_space",
        })
    }
}

/// [`Target`]'s runtime status: metadata and data usage, the mode the
/// pool has fallen into, and whether it wants checking.
///
/// An enum because a failed pool reports the single keyword `Fail`
/// instead of any of the fields below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Info {
    /// The pool is operating.
    Active {
        /// The current transaction id, which
        /// `set_transaction_id` advances.
        transaction_id: u64,
        /// Metadata blocks in use.
        used_metadata_blocks: u64,
        /// Metadata blocks in total. Approaching this drops the pool to
        /// read-only.
        total_metadata_blocks: u64,
        /// Data blocks in use.
        used_data_blocks: u64,
        /// Data blocks in total.
        total_data_blocks: u64,
        /// The metadata snapshot block held by `reserve_metadata_snap`,
        /// or `None` when none is held.
        held_metadata_root: Option<u64>,
        /// The mode the pool is serving I/O in.
        access_mode: AccessMode,
        /// How discards are handled.
        discard_mode: DiscardMode,
        /// What happens to writes when the data device is full.
        out_of_space_policy: OutOfSpacePolicy,
        /// Whether the pool wants an offline metadata check before it can
        /// be trusted again.
        needs_check: bool,
        /// The free-metadata threshold, in blocks, at which the kernel
        /// raises a low-water event.
        metadata_low_watermark_blocks: u64,
    },

    /// The pool has failed; no other field is reported.
    Fail,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Info::Active {
            transaction_id,
            used_metadata_blocks,
            total_metadata_blocks,
            used_data_blocks,
            total_data_blocks,
            held_metadata_root,
            access_mode,
            discard_mode,
            out_of_space_policy,
            needs_check,
            metadata_low_watermark_blocks,
        } = self
        else {
            return f.write_str("Fail");
        };

        write!(
            f,
            "{transaction_id} {} {} ",
            Fraction::from((*used_metadata_blocks, *total_metadata_blocks)),
            Fraction::from((*used_data_blocks, *total_data_blocks)),
        )?;
        match held_metadata_root {
            Some(block) => write!(f, "{block} ")?,
            None => f.write_str("- ")?,
        }
        write!(f, "{access_mode} {discard_mode} {out_of_space_policy} ")?;
        f.write_str(if *needs_check { "needs_check " } else { "- " })?;
        // The kernel's own status ends with a trailing space after this
        // final field; matching it keeps a parsed row re-rendering byte
        // for byte.
        write!(f, "{metadata_low_watermark_blocks} ")
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim() == "Fail" {
            return Ok(Info::Fail);
        }
        let mut fields = s.split_whitespace();
        let transaction_id = fields.next().ok_or(ParseError)?.parse()?;
        let (used_metadata_blocks, total_metadata_blocks) = fields
            .next()
            .ok_or(ParseError)?
            .parse::<Fraction<u64>>()?
            .into();
        let (used_data_blocks, total_data_blocks) = fields
            .next()
            .ok_or(ParseError)?
            .parse::<Fraction<u64>>()?
            .into();
        let held_metadata_root = match fields.next().ok_or(ParseError)? {
            "-" => None,
            block => Some(block.parse()?),
        };
        let access_mode = fields.next().ok_or(ParseError)?.parse()?;
        let discard_mode = fields.next().ok_or(ParseError)?.parse()?;
        let out_of_space_policy = fields.next().ok_or(ParseError)?.parse()?;
        let needs_check = match fields.next().ok_or(ParseError)? {
            "needs_check" => true,
            "-" => false,
            _ => return Err(ParseError),
        };
        let metadata_low_watermark_blocks = fields.next().ok_or(ParseError)?.parse()?;
        if fields.next().is_some() {
            return Err(ParseError);
        }
        Ok(Info::Active {
            transaction_id,
            used_metadata_blocks,
            total_metadata_blocks,
            used_data_blocks,
            total_data_blocks,
            held_metadata_root,
            access_mode,
            discard_mode,
            out_of_space_policy,
            needs_check,
            metadata_low_watermark_blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line<T: DmTarget + std::fmt::Display>(start: u64, length: u64, value: &T) -> String {
        let parameters = value.to_string();
        if parameters.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {parameters}", T::NAME)
        }
    }

    #[test]
    fn thin_pool_renders_only_set_feature_flags() {
        let t = Target::builder(
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            128,
            0,
        )
        .no_discard_passdown(true)
        .error_if_no_space(true)
        .build();
        assert_eq!(
            line(0, 1_048_576, &t),
            "0 1048576 thin-pool 252:1 252:2 128 0 2 no_discard_passdown error_if_no_space"
        );
    }

    #[test]
    fn thin_pool_display_from_str_round_trips_every_flag() {
        let base = || {
            Target::builder(
                DevId::new(252, 1).unwrap(),
                DevId::new(252, 2).unwrap(),
                128,
                64,
            )
        };
        let cases = [
            base().build(),
            base().skip_block_zeroing(true).build(),
            base().ignore_discard(true).build(),
            base().no_discard_passdown(true).build(),
            base().read_only(true).build(),
            base().error_if_no_space(true).build(),
            base()
                .skip_block_zeroing(true)
                .ignore_discard(true)
                .no_discard_passdown(true)
                .read_only(true)
                .error_if_no_space(true)
                .build(),
        ];
        for original in cases {
            assert_eq!(
                original.to_string().parse::<Target>().as_ref(),
                Ok(&original)
            );
        }
    }

    #[test]
    fn thin_pool_from_str_rejects_a_count_disagreeing_with_the_flags() {
        assert!("252:1 252:2 128 0 2 read_only".parse::<Target>().is_err());
        assert!("252:1 252:2 128 0 0 read_only".parse::<Target>().is_err());
    }

    #[test]
    fn thin_pool_from_str_rejects_an_unknown_flag() {
        assert!(
            "252:1 252:2 128 0 1 no_such_flag"
                .parse::<Target>()
                .is_err()
        );
    }
}
