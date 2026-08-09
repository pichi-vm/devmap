// SPDX-License-Identifier: Apache-2.0

//! The `integrity` (dm-integrity) target: adds per-block integrity tags to
//! a device so silent data corruption can be detected.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, RawInfo, Target};

/// [`Integrity`]'s write mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mode {
    /// Direct writes, no journal.
    Direct,
    /// Journaled writes.
    Journaled,
    /// Bitmap mode.
    Bitmap,
    /// Recovery mode.
    Recovery,
    /// Inline mode: tags stored in the underlying device's own integrity
    /// profile.
    Inline,
}
impl Mode {
    /// The single-character mode token used in the table line.
    fn as_char(self) -> char {
        match self {
            Mode::Direct => 'D',
            Mode::Journaled => 'J',
            Mode::Bitmap => 'B',
            Mode::Recovery => 'R',
            Mode::Inline => 'I',
        }
    }

    fn from_token(token: &str) -> Result<Self, ParseError> {
        match token {
            "D" => Ok(Mode::Direct),
            "J" => Ok(Mode::Journaled),
            "B" => Ok(Mode::Bitmap),
            "R" => Ok(Mode::Recovery),
            "I" => Ok(Mode::Inline),
            _ => Err(ParseError),
        }
    }
}

/// Adds per-block integrity tags to `device`, detecting silent data
/// corruption. Only `internal_hash`/`allow_discards` are exposed; the
/// journal/crypto/bitmap-tuning arguments are locked out. Build via
/// [`Integrity::builder`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Integrity {
    device: DevId,
    reserved_sectors: u64,
    tag_size: Option<u32>,
    mode: Mode,
    internal_hash: Option<String>,
    allow_discards: bool,
}
impl Integrity {
    /// Start building an [`Integrity`]. `tag_size`/`internal_hash`
    /// default to unset and `allow_discards` to false.
    #[must_use]
    pub fn builder(device: DevId, reserved_sectors: u64, mode: Mode) -> Builder {
        Builder {
            device,
            reserved_sectors,
            mode,
            tag_size: None,
            internal_hash: None,
            allow_discards: false,
        }
    }

    /// The device being protected.
    #[must_use]
    pub fn device(&self) -> DevId {
        self.device
    }
    /// Sectors reserved at the start of the device.
    #[must_use]
    pub fn reserved_sectors(&self) -> u64 {
        self.reserved_sectors
    }
    /// The per-block tag size in bytes, if set.
    #[must_use]
    pub fn tag_size(&self) -> Option<u32> {
        self.tag_size
    }
    /// The write mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }
    /// The internal hash algorithm, if set.
    #[must_use]
    pub fn internal_hash(&self) -> Option<&str> {
        self.internal_hash.as_deref()
    }
    /// Whether discards are allowed to pass through.
    #[must_use]
    pub fn allow_discards(&self) -> bool {
        self.allow_discards
    }
}
impl Target for Integrity {
    const NAME: &'static str = "integrity";
    type Info = RawInfo;
}
impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = self.mode.as_char();
        write!(f, "{} {} ", self.device, self.reserved_sectors)?;
        match self.tag_size {
            Some(size) => write!(f, "{size}")?,
            None => f.write_char('-')?,
        }
        write!(f, " {mode}")?;
        let opt_count = u32::from(self.internal_hash.is_some()) + u32::from(self.allow_discards);
        write!(f, " {opt_count}")?;
        if let Some(alg) = &self.internal_hash {
            write!(f, " internal_hash:{alg}")?;
        }
        if self.allow_discards {
            write!(f, " allow_discards")?;
        }
        Ok(())
    }
}

/// The `integrity` table row as the kernel reports it.
///
/// dm-integrity is the one target in this crate whose read shape isn't its
/// write shape. It answers `DM_TABLE_STATUS` with its whole effective
/// configuration, not the arguments that were loaded: a concrete
/// `tag_size` in place of the `-` that asked it to derive one, plus the
/// journal, bitmap, and buffer geometry it sized for itself from the
/// device. None of that fits [`Integrity`], whose fields describe what a
/// caller can ask for.
///
/// Fields are plain and public because this type only ever comes off the
/// wire — there is nothing to validate on construction and no invariant
/// between them to protect.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::struct_excessive_bools)] // mirrors dm-integrity's bare status flags
pub struct Table {
    /// The device being protected.
    pub device: DevId,
    /// Sectors reserved at the start of the device.
    pub reserved_sectors: u64,
    /// The per-block tag size in bytes. Always concrete here, even when
    /// the loaded table left it to the kernel to derive.
    pub tag_size: u32,
    /// The write mode.
    pub mode: Mode,
    /// A separate metadata device, if the mapping uses one.
    pub meta_device: Option<DevId>,
    /// The block size in bytes, reported only when it isn't one sector.
    pub block_size: Option<u32>,
    /// Whether a background tag recalculation is in progress.
    pub recalculating: bool,
    /// Whether the recalculate flag is reset on the next load.
    pub reset_recalculate: bool,
    /// Whether discards pass through.
    pub allow_discards: bool,
    /// The metadata interleave granularity. Absent in [`Mode::Inline`].
    pub interleave_sectors: Option<u32>,
    /// The metadata buffer size in sectors. Always reported.
    pub buffer_sectors: u32,
    /// Journal size in sectors. [`Mode::Journaled`] only.
    pub journal_sectors: Option<u32>,
    /// Journal fill percentage that triggers writeback.
    /// [`Mode::Journaled`] only.
    pub journal_watermark_percent: Option<u32>,
    /// Autocommit interval in milliseconds. [`Mode::Journaled`] only.
    pub commit_time_ms: Option<u32>,
    /// Sectors covered by one bitmap bit. [`Mode::Bitmap`] only.
    pub sectors_per_bit: Option<u64>,
    /// Bitmap flush interval in milliseconds. [`Mode::Bitmap`] only.
    pub bitmap_flush_interval_ms: Option<u32>,
    /// Whether the fixed-padding superblock flag is set.
    pub fix_padding: bool,
    /// Whether the fixed-HMAC superblock flag is set.
    pub fix_hmac: bool,
    /// Whether legacy recalculation is permitted.
    pub legacy_recalculate: bool,
    /// The internal hash spec, `algorithm` or `algorithm:key`.
    pub internal_hash: Option<String>,
    /// The journal encryption spec, `algorithm` or `algorithm:key`.
    pub journal_crypt: Option<String>,
    /// The journal MAC spec, `algorithm` or `algorithm:key`.
    pub journal_mac: Option<String>,
}

/// The value half of a `key:value` status argument, parsed as `T`. A free
/// function rather than a closure because `sectors_per_bit` is a `u64` and
/// every other numeric argument is a `u32`.
fn number<T: FromStr>(value: Option<&str>) -> Result<T, ParseError> {
    value.ok_or(ParseError)?.parse().map_err(|_| ParseError)
}

impl FromStr for Table {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let device = p.device()?;
        let reserved_sectors = p.value()?;
        let tag_size = p.value()?;
        let mode = Mode::from_token(p.token()?)?;

        let mut table = Table {
            device,
            reserved_sectors,
            tag_size,
            mode,
            meta_device: None,
            block_size: None,
            recalculating: false,
            reset_recalculate: false,
            allow_discards: false,
            interleave_sectors: None,
            buffer_sectors: 0,
            journal_sectors: None,
            journal_watermark_percent: None,
            commit_time_ms: None,
            sectors_per_bit: None,
            bitmap_flush_interval_ms: None,
            fix_padding: false,
            fix_hmac: false,
            legacy_recalculate: false,
            internal_hash: None,
            journal_crypt: None,
            journal_mac: None,
        };

        // Every argument is a single token, either a bare flag or a
        // `key:value` pair, so the count is a token count. The algorithm
        // specs keep their value verbatim: it is `alg` or `alg:key`, and
        // the key half may itself contain colons.
        let count: usize = p.value()?;
        for _ in 0..count {
            let arg = p.token()?;
            let (key, value) = match arg.split_once(':') {
                Some((key, value)) => (key, Some(value)),
                None => (arg, None),
            };
            let text = || value.ok_or(ParseError).map(str::to_owned);
            match key {
                "meta_device" => {
                    table.meta_device = Some(
                        crate::table::parse_device(value.ok_or(ParseError)?).ok_or(ParseError)?,
                    );
                }
                "block_size" => table.block_size = Some(number(value)?),
                "recalculate" => table.recalculating = true,
                "reset_recalculate" => table.reset_recalculate = true,
                "allow_discards" => table.allow_discards = true,
                "interleave_sectors" => table.interleave_sectors = Some(number(value)?),
                "buffer_sectors" => table.buffer_sectors = number(value)?,
                "journal_sectors" => table.journal_sectors = Some(number(value)?),
                "journal_watermark" => table.journal_watermark_percent = Some(number(value)?),
                "commit_time" => table.commit_time_ms = Some(number(value)?),
                "sectors_per_bit" => table.sectors_per_bit = Some(number(value)?),
                "bitmap_flush_interval" => table.bitmap_flush_interval_ms = Some(number(value)?),
                "fix_padding" => table.fix_padding = true,
                "fix_hmac" => table.fix_hmac = true,
                "legacy_recalculate" => table.legacy_recalculate = true,
                "internal_hash" => table.internal_hash = Some(text()?),
                "journal_crypt" => table.journal_crypt = Some(text()?),
                "journal_mac" => table.journal_mac = Some(text()?),
                _ => return Err(ParseError),
            }
        }
        p.end()?;
        Ok(table)
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Argument order follows dm-integrity's own status emission, so a
        // parsed row renders back byte-for-byte.
        let mut args: Vec<String> = Vec::new();
        if let Some(meta_device) = self.meta_device {
            args.push(format!("meta_device:{meta_device}"));
        }
        if let Some(block_size) = self.block_size {
            args.push(format!("block_size:{block_size}"));
        }
        for (set, name) in [
            (self.recalculating, "recalculate"),
            (self.reset_recalculate, "reset_recalculate"),
            (self.allow_discards, "allow_discards"),
        ] {
            if set {
                args.push(name.to_owned());
            }
        }
        if let Some(interleave_sectors) = self.interleave_sectors {
            args.push(format!("interleave_sectors:{interleave_sectors}"));
        }
        args.push(format!("buffer_sectors:{}", self.buffer_sectors));
        if let Some(journal_sectors) = self.journal_sectors {
            args.push(format!("journal_sectors:{journal_sectors}"));
        }
        if let Some(percent) = self.journal_watermark_percent {
            args.push(format!("journal_watermark:{percent}"));
        }
        if let Some(commit_time_ms) = self.commit_time_ms {
            args.push(format!("commit_time:{commit_time_ms}"));
        }
        if let Some(sectors_per_bit) = self.sectors_per_bit {
            args.push(format!("sectors_per_bit:{sectors_per_bit}"));
        }
        if let Some(interval) = self.bitmap_flush_interval_ms {
            args.push(format!("bitmap_flush_interval:{interval}"));
        }
        for (set, name) in [
            (self.fix_padding, "fix_padding"),
            (self.fix_hmac, "fix_hmac"),
            (self.legacy_recalculate, "legacy_recalculate"),
        ] {
            if set {
                args.push(name.to_owned());
            }
        }
        for (spec, name) in [
            (&self.internal_hash, "internal_hash"),
            (&self.journal_crypt, "journal_crypt"),
            (&self.journal_mac, "journal_mac"),
        ] {
            if let Some(spec) = spec {
                args.push(format!("{name}:{spec}"));
            }
        }

        write!(
            f,
            "{} {} {} {} {}",
            self.device,
            self.reserved_sectors,
            self.tag_size,
            self.mode.as_char(),
            args.len()
        )?;
        for arg in &args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

/// Builder for [`Integrity`] — see [`Integrity::builder`].
#[derive(Debug, Clone)]
pub struct Builder {
    device: DevId,
    reserved_sectors: u64,
    mode: Mode,
    tag_size: Option<u32>,
    internal_hash: Option<String>,
    allow_discards: bool,
}
impl Builder {
    /// Per-block integrity tag size in bytes.
    #[must_use]
    pub fn tag_size(mut self, bytes: u32) -> Self {
        self.tag_size = Some(bytes);
        self
    }
    /// Compute internal tags with this hash algorithm (e.g. `"sha256"`).
    #[must_use]
    pub fn internal_hash(mut self, algorithm: impl Into<String>) -> Self {
        self.internal_hash = Some(algorithm.into());
        self
    }
    /// Allow discards to pass through.
    #[must_use]
    pub fn allow_discards(mut self, on: bool) -> Self {
        self.allow_discards = on;
        self
    }
    /// Finish building the [`Integrity`].
    #[must_use]
    pub fn build(self) -> Integrity {
        Integrity {
            device: self.device,
            reserved_sectors: self.reserved_sectors,
            tag_size: self.tag_size,
            mode: self.mode,
            internal_hash: self.internal_hash,
            allow_discards: self.allow_discards,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::NAME)
        } else {
            format!("{start} {length} {} {params}", T::NAME)
        }
    }

    #[test]
    fn integrity_renders_dash_for_unset_tag_size() {
        // internal_hash lets the kernel derive the tag size, so tag_size
        // may stay unset (renders `-`).
        let t = Integrity::builder(DevId::new(252, 1).unwrap(), 0, Mode::Journaled)
            .internal_hash("sha256")
            .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 integrity 252:1 0 - J 1 internal_hash:sha256"
        );
    }

    #[test]
    fn integrity_renders_optional_args() {
        let t = Integrity::builder(DevId::new(252, 1).unwrap(), 0, Mode::Direct)
            .tag_size(32)
            .internal_hash("sha256")
            .allow_discards(true)
            .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 integrity 252:1 0 32 D 2 internal_hash:sha256 allow_discards"
        );
    }

    #[test]
    fn integrity_renders_mode_chars() {
        let bitmap = Integrity::builder(DevId::new(252, 1).unwrap(), 0, Mode::Bitmap)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &bitmap).contains(" B "));
        let recovery = Integrity::builder(DevId::new(252, 1).unwrap(), 0, Mode::Recovery)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &recovery).contains(" R "));
        let inline = Integrity::builder(DevId::new(252, 1).unwrap(), 0, Mode::Inline)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &inline).contains(" I "));
    }

    // The line a 5.x kernel actually returned for a table loaded as
    // `7:0 0 - J 1 internal_hash:sha256` — a concrete tag size in place of
    // the `-`, plus the geometry it chose for itself.
    const REPORTED: &str = "7:0 0 32 J 6 interleave_sectors:32768 buffer_sectors:128 \
                            journal_sectors:440 journal_watermark:50 commit_time:10000 \
                            internal_hash:sha256";

    #[test]
    fn table_reads_what_the_kernel_reported() {
        let table: Table = REPORTED.parse().unwrap();
        assert_eq!(table.device, DevId::new(7, 0).unwrap());
        assert_eq!(table.tag_size, 32);
        assert_eq!(table.mode, Mode::Journaled);
        assert_eq!(table.interleave_sectors, Some(32768));
        assert_eq!(table.buffer_sectors, 128);
        assert_eq!(table.journal_sectors, Some(440));
        assert_eq!(table.journal_watermark_percent, Some(50));
        assert_eq!(table.commit_time_ms, Some(10000));
        assert_eq!(table.internal_hash.as_deref(), Some("sha256"));
        assert!(!table.allow_discards);
        assert_eq!(table.meta_device, None);
    }

    #[test]
    fn table_display_from_str_round_trips_in_kernel_argument_order() {
        let table: Table = REPORTED.parse().unwrap();
        assert_eq!(table.to_string(), REPORTED);
        assert_eq!(table.to_string().parse::<Table>().as_ref(), Ok(&table));
    }

    #[test]
    fn table_holds_what_integrity_cannot() {
        // The write shape renders a `-` asking the kernel to derive a tag
        // size; the read shape has no way to express that, and no way to
        // lose the answer.
        let written = Integrity::builder(DevId::new(7, 0).unwrap(), 0, Mode::Journaled)
            .internal_hash("sha256")
            .build();
        assert_eq!(written.to_string(), "7:0 0 - J 1 internal_hash:sha256");
        assert_eq!(written.tag_size(), None);
        assert_eq!(REPORTED.parse::<Table>().unwrap().tag_size, 32);
    }

    #[test]
    fn table_round_trips_bitmap_and_meta_device_rows() {
        for line in [
            "7:0 0 32 B 5 meta_device:7:1 block_size:4096 buffer_sectors:128 \
             sectors_per_bit:8192 bitmap_flush_interval:10000",
            "7:0 0 32 I 1 buffer_sectors:128",
            "7:0 0 32 D 6 recalculate allow_discards interleave_sectors:32768 \
             buffer_sectors:128 fix_hmac internal_hash:hmac(sha256):0011ff",
        ] {
            let table: Table = line.parse().unwrap_or_else(|_| panic!("parse {line:?}"));
            assert_eq!(table.to_string(), line);
        }
    }

    #[test]
    fn table_keeps_a_colon_bearing_algorithm_key_whole() {
        let table: Table = "7:0 0 32 J 2 buffer_sectors:128 internal_hash:hmac(sha256):00:11"
            .parse()
            .unwrap();
        assert_eq!(table.internal_hash.as_deref(), Some("hmac(sha256):00:11"));
    }

    #[test]
    fn table_rejects_rows_it_cannot_hold() {
        // An argument count disagreeing with the arguments, an unknown
        // argument, and an unknown mode.
        for line in [
            "7:0 0 32 J 3 buffer_sectors:128",
            "7:0 0 32 J 1 buffer_sectors:128 commit_time:10000",
            "7:0 0 32 J 2 buffer_sectors:128 no_such_argument",
            "7:0 0 32 X 1 buffer_sectors:128",
            "7:0 0 - J 1 buffer_sectors:128",
        ] {
            assert!(line.parse::<Table>().is_err(), "{line}");
        }
    }
}
