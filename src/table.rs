// SPDX-License-Identifier: Apache-2.0

//! The trait-based dm target model.
//!
//! [`Target`] names a kernel target type and its runtime-status type; each
//! concrete target (in [`crate::targets`]) is a struct implementing it, with
//! [`std::fmt::Display`] as the param encoder and [`std::str::FromStr`] as
//! the decoder (both required only where used, never as supertraits).
//!
//! [`TableBuilder`] streams targets into a single `DM_TABLE_LOAD` buffer.
//! [`Row`] is one row of a `DM_TABLE_STATUS` response, tagged by [`mode`]
//! ([`mode::Spec`] for the table, [`mode::Info`] for runtime status); its
//! params are reached only through the mode-checked [`Row::parse`].

use std::fmt::{self, Write as _};
use std::fs::File;
use std::marker::PhantomData;
use std::str::FromStr;
use std::sync::Arc;

use zerocopy::{FromBytes, IntoBytes};

use crate::Error;
use crate::device::{DevId, check_version};
use crate::header::DmHeader;
use crate::uapi::{DM_MAX_TYPE_NAME, DM_TABLE_LOAD, DM_TARGET_SPEC_SIZE, dm_target_spec_raw};

/// A device-mapper target type: its kernel name and its runtime-status type.
///
/// The param codec lives on std traits applied at the use site, not here:
/// writing a table needs `Self: Display` (the params), and reconstructing a
/// target from a `DM_TABLE_STATUS` (table) row needs `Self: FromStr`.
/// Implementors must render NUL-free, whitespace-correct params — the
/// builder rejects an interior NUL, but field-level correctness is the
/// target's own responsibility (validate in its constructor).
pub trait Target: Sized {
    /// The kernel `target_type` name, e.g. `"linear"`. Must be non-empty,
    /// shorter than 16 bytes, and free of NUL/whitespace.
    const TYPE_NAME: &'static str;

    /// This target's `STATUSTYPE_INFO` runtime-status type. Targets whose
    /// status this crate doesn't model set `type Info = RawInfo`.
    type Info: FromStr;
}

/// The uninterpreted status string of a target whose typed status this
/// crate doesn't model. Its [`FromStr`] never fails.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawInfo(pub String);

impl FromStr for RawInfo {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RawInfo(s.to_owned()))
    }
}

/// Error returned by a target's [`FromStr`] when a status/table string
/// doesn't match the expected grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed dm target params")
    }
}
impl std::error::Error for ParseError {}

/// Mode markers distinguishing the two `DM_TABLE_STATUS` payloads.
pub mod mode {
    /// `STATUSTYPE_TABLE`: the construction parameters (reconstruct a target).
    #[derive(Debug)]
    pub enum Spec {}
    /// `STATUSTYPE_INFO`: per-target runtime status.
    #[derive(Debug)]
    pub enum Info {}

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Spec {}
        impl Sealed for super::Info {}
    }

    /// Sealed marker implemented only by [`Spec`] and [`Info`].
    pub trait Mode: sealed::Sealed {}
    impl Mode for Spec {}
    impl Mode for Info {}
}

/// One `<start> <length> <target>` row of a `DM_TABLE_STATUS` response,
/// tagged by its [`mode`]. The params string is private: reach it through
/// the mode-checked [`Row::parse`], which returns the reconstructed target
/// ([`mode::Spec`]) or its runtime status ([`mode::Info`]).
///
/// The mode tag is load-bearing: a [`mode::Info`] row exposes only
/// `parse::<T>() -> Option<T::Info>` (runtime status), never a
/// reconstructed target — the target-returning `parse` is defined solely
/// on `Row<mode::Spec>`. This will not compile:
///
/// ```compile_fail
/// # use devmap::{Row, mode, targets::Linear};
/// fn wrong(row: Row<mode::Info>) {
///     // `parse::<Linear>()` on an Info row would return `Option<Linear::Info>`,
///     // and `let _: Option<Linear>` forces the target interpretation the
///     // Info mode never provides — a type error.
///     let _target: Option<Linear> = row.parse::<Linear>();
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Row<M: mode::Mode> {
    start: u64,
    length: u64,
    type_name: String,
    params: String,
    _mode: PhantomData<M>,
}

impl<M: mode::Mode> Row<M> {
    /// The row's starting sector.
    pub fn start(&self) -> u64 {
        self.start
    }
    /// The row's length in sectors.
    pub fn length(&self) -> u64 {
        self.length
    }
    /// The kernel target type name for this row.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
}

impl Row<mode::Spec> {
    /// Reconstruct the target `T` from this table row, or `None` if the
    /// row is a different target type or the params don't parse.
    pub fn parse<T: Target + FromStr>(&self) -> Option<T> {
        if self.type_name == T::TYPE_NAME {
            self.params.parse::<T>().ok()
        } else {
            None
        }
    }
}

impl Row<mode::Info> {
    /// Parse this status row as target `T`'s runtime status
    /// ([`Target::Info`]), or `None` on a type-name or parse mismatch.
    pub fn parse<T: Target>(&self) -> Option<T::Info> {
        if self.type_name == T::TYPE_NAME {
            self.params.parse::<T::Info>().ok()
        } else {
            None
        }
    }
}

impl<M: mode::Mode> fmt::Display for Row<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.params.is_empty() {
            write!(f, "{} {} {}", self.start, self.length, self.type_name)
        } else {
            write!(
                f,
                "{} {} {} {}",
                self.start, self.length, self.type_name, self.params
            )
        }
    }
}

/// A streaming builder for `DM_TABLE_LOAD`: each [`add`](TableBuilder::add)
/// renders a target directly into one growing buffer. Terminate with
/// [`load`](TableBuilder::load). Obtained from [`crate::Device::builder`].
#[derive(Debug)]
pub struct TableBuilder {
    control: Arc<File>,
    buf: Vec<u8>,
    count: u32,
    last_spec_off: Option<usize>,
    rendered: Vec<String>,
}

impl TableBuilder {
    pub(crate) fn new(control: Arc<File>, dev: DevId) -> Self {
        let mut buf = Vec::with_capacity(DmHeader::SIZE + 256);
        buf.extend_from_slice(DmHeader::by_dev(dev.to_dev_t()).as_bytes());
        Self {
            control,
            buf,
            count: 0,
            last_spec_off: None,
            rendered: Vec::new(),
        }
    }

    /// Append a target mapping sectors `[start, start + length)`.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] if `T::TYPE_NAME` is invalid, or if the target
    /// renders an interior NUL into its params (which would truncate the
    /// table line).
    // Table buffers never approach u32::MAX; the kernel's own fields are u32.
    // `target` is taken by value (the builder owns each row's rendering) even
    // though it's only read through `Display`.
    #[allow(clippy::cast_possible_truncation, clippy::needless_pass_by_value)]
    pub fn add<T: Target + fmt::Display>(
        mut self,
        start: u64,
        length: u64,
        target: T,
    ) -> Result<Self, Error> {
        let name = T::TYPE_NAME.as_bytes();
        if name.is_empty()
            || name.len() >= DM_MAX_TYPE_NAME
            || name.iter().any(|b| *b == 0 || b.is_ascii_whitespace())
        {
            return Err(Error::Usage(format!(
                "invalid dm target type name: {:?}",
                T::TYPE_NAME
            )));
        }

        let mut params = String::new();
        write!(params, "{target}").expect("Display into String is infallible");
        if params.as_bytes().contains(&0) {
            return Err(Error::Usage(format!(
                "target {} rendered an interior NUL in its params",
                T::TYPE_NAME
            )));
        }

        let spec_off = self.buf.len();
        if let Some(prev) = self.last_spec_off {
            // Write-side `next`: byte offset from the previous spec's start
            // to this one.
            let delta = (spec_off - prev) as u32;
            self.buf[prev + 20..prev + 24].copy_from_slice(&delta.to_ne_bytes());
        }

        let mut target_type = [0u8; DM_MAX_TYPE_NAME];
        target_type[..name.len()].copy_from_slice(name);
        let spec = dm_target_spec_raw {
            sector_start: start,
            length,
            status: 0,
            next: 0,
            target_type,
        };
        self.buf.extend_from_slice(spec.as_bytes());

        self.buf.extend_from_slice(params.as_bytes());
        self.buf.push(0);
        let block = DM_TARGET_SPEC_SIZE + params.len() + 1;
        self.buf.resize(spec_off + block.next_multiple_of(8), 0);

        self.rendered.push(if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        });
        self.last_spec_off = Some(spec_off);
        self.count += 1;
        Ok(self)
    }

    /// Issue `DM_TABLE_LOAD`, staging the accumulated table into the
    /// device's inactive slot. Activate with [`crate::Device::resume`].
    ///
    /// # Errors
    ///
    /// [`Error::DmIoctl`] (with the rendered table attached) if the kernel
    /// rejects the table.
    // The `mut_from_prefix` expects never fire: the buffer always begins with
    // a `DmHeader` (written in `new`), so this is not a real panic path.
    #[allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]
    pub fn load(mut self) -> Result<(), Error> {
        let total = self.buf.len() as u32;
        {
            let (header, _) =
                DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
            let header: &mut DmHeader = header;
            header.set_data_size(total);
            header.set_target_count(self.count);
        }
        let (header, _) =
            DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
        let header: &mut DmHeader = header;
        DM_TABLE_LOAD
            .ioctl(&*self.control, header)
            .map_err(|source| Error::DmIoctl {
                op: "DM_TABLE_LOAD",
                source,
                // ` | `-joined so the whole error stays on one line in loggers;
                // omitted entirely for an empty table so there's no `(table: )`.
                table_line: (!self.rendered.is_empty()).then(|| self.rendered.join(" | ")),
            })?;
        check_version("DM_TABLE_LOAD", header)
    }
}

/// Parses a `DM_TABLE_STATUS` response into [`Row`]s. Not exported —
/// `Device::table`/`Device::info` return `impl Iterator<Item = Row<_>>`.
///
/// `dm_target_spec.next` here is the byte offset from the *first* spec's
/// start to the next one (the read-direction convention, opposite the
/// write side — see `<linux/dm-ioctl.h>`).
pub(crate) struct TableStatusIter<M: mode::Mode> {
    buf: Vec<u8>,
    first: usize,
    offset: usize,
    remaining: u32,
    _mode: PhantomData<M>,
}

impl<M: mode::Mode> TableStatusIter<M> {
    /// `data_start` is the kernel-reported offset of the first spec (the
    /// base for read-side `next`); callers pass it clamped to `buf.len()`.
    pub(crate) fn new(buf: Vec<u8>, data_start: usize, target_count: u32) -> Self {
        Self {
            buf,
            first: data_start,
            offset: data_start,
            remaining: target_count,
            _mode: PhantomData,
        }
    }
}

impl<M: mode::Mode> Iterator for TableStatusIter<M> {
    type Item = Row<M>;

    // The fixed-width `try_into().unwrap()`s below operate on a slice bounded
    // to exactly `DM_TARGET_SPEC_SIZE`, so they cannot panic.
    #[allow(clippy::missing_panics_doc)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // `checked_add` guards against a kernel-controlled `next` overflowing
        // `usize` on 32-bit targets; on overflow we simply stop.
        let end = self.offset.checked_add(DM_TARGET_SPEC_SIZE)?;
        if end > self.buf.len() {
            return None;
        }

        let spec = &self.buf[self.offset..end];
        let sector_start = u64::from_ne_bytes(spec[0..8].try_into().unwrap());
        let length = u64::from_ne_bytes(spec[8..16].try_into().unwrap());
        let next = u32::from_ne_bytes(spec[20..24].try_into().unwrap());
        let type_field = &spec[24..24 + DM_MAX_TYPE_NAME];
        let type_nul = type_field
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(type_field.len());
        let type_name = String::from_utf8_lossy(&type_field[..type_nul]).into_owned();

        let param_area = &self.buf[end..];
        let param_nul = param_area
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(param_area.len());
        let params = String::from_utf8_lossy(&param_area[..param_nul]).into_owned();

        self.remaining -= 1;
        self.offset = if next == 0 {
            self.buf.len()
        } else {
            self.first.saturating_add(next as usize)
        };

        Some(Row {
            start: sector_start,
            length,
            type_name,
            params,
            _mode: PhantomData,
        })
    }
}

/// Parse a `major:minor` device token.
pub(crate) fn parse_device(s: &str) -> Option<DevId> {
    let (maj, min) = s.split_once(':')?;
    Some(DevId::new(maj.parse().ok()?, min.parse().ok()?))
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures: sizes are tiny, never near u32::MAX
mod tests {
    use super::*;
    use crate::targets::{self, Linear, Verity};

    /// An `Arc<File>` for a `TableBuilder` that never issues a real ioctl:
    /// the rendering/validation paths run entirely before `load`.
    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    // --- Builder buffer layout -------------------------------------------
    //
    // `mod tests` is inside the `table` module, so it reads `TableBuilder`'s
    // private `buf` directly — no public accessor is added to the lib. This
    // ports the old `DmTableBuf::build` byte-layout spot checks.

    #[test]
    fn buf_for_zero_target_has_correct_layout() {
        let b = TableBuilder::new(dummy_control(), DevId::new(252, 5))
            .add(0, 8, targets::Zero)
            .expect("add zero");
        // header + (40 spec + 0 params + 1 NUL = 41 -> padded to 48).
        assert_eq!(b.buf.len(), DmHeader::SIZE + 48);
    }

    #[test]
    fn buf_for_linear_target_has_correct_layout_and_params() {
        let b = TableBuilder::new(dummy_control(), DevId::new(252, 9))
            .add(
                0,
                1024,
                Linear {
                    device: DevId::new(252, 5),
                    offset_sectors: 0,
                },
            )
            .expect("add linear");
        let params = "252:5 0";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(b.buf.len(), DmHeader::SIZE + aligned);

        let bytes = &b.buf;
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(
            &bytes[param_start..param_start + params.len()],
            params.as_bytes()
        );
        assert_eq!(bytes[param_start + params.len()], 0); // NUL terminator
        let type_field = &bytes[DmHeader::SIZE + 24..DmHeader::SIZE + 24 + DM_MAX_TYPE_NAME];
        assert_eq!(&type_field[..6], b"linear");
    }

    #[test]
    fn buf_for_verity_target_has_correct_layout_and_params() {
        let t = Verity::new(
            DevId::new(253, 3),
            DevId::new(253, 4),
            7,
            "sha256",
            vec![0xCD; 32],
            vec![0x55; 32],
        );
        let b = TableBuilder::new(dummy_control(), DevId::new(252, 9))
            .add(0, 56, t)
            .expect("add verity");
        let cd_hex = "cd".repeat(32);
        let salt_hex = "55".repeat(32);
        let params = format!("1 253:3 253:4 4096 4096 7 1 sha256 {cd_hex} {salt_hex}");
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(b.buf.len(), DmHeader::SIZE + aligned);

        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(
            &b.buf[param_start..param_start + params.len()],
            params.as_bytes()
        );
        assert_eq!(b.buf[param_start + params.len()], 0);
    }

    #[test]
    fn buf_for_three_target_table_chains_specs_with_offsets_relative_to_current() {
        // Write-side `next` is relative to *each spec's own* start (unlike
        // the read side). Three lines, not two: with only two, the first
        // spec's `next` can't distinguish "relative to current" from
        // "relative to first".
        let b = TableBuilder::new(dummy_control(), DevId::new(252, 9))
            .add(0, 8, targets::Zero)
            .and_then(|b| {
                b.add(
                    8,
                    1024,
                    Linear {
                        device: DevId::new(252, 5),
                        offset_sectors: 5,
                    },
                )
            })
            .and_then(|b| b.add(1032, 8, targets::Error))
            .expect("build three-target table");
        let bytes = &b.buf;

        let zero_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        let linear_aligned = (DM_TARGET_SPEC_SIZE + "252:5 5".len() + 1).next_multiple_of(8);
        let error_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        assert_eq!(
            bytes.len(),
            DmHeader::SIZE + zero_aligned + linear_aligned + error_aligned
        );

        let spec0 = DmHeader::SIZE;
        let spec1 = spec0 + zero_aligned;
        let spec2 = spec1 + linear_aligned;

        let next0 = u32::from_ne_bytes(bytes[spec0 + 20..spec0 + 24].try_into().unwrap());
        let next1 = u32::from_ne_bytes(bytes[spec1 + 20..spec1 + 24].try_into().unwrap());
        let next2 = u32::from_ne_bytes(bytes[spec2 + 20..spec2 + 24].try_into().unwrap());

        assert_eq!(
            next0, zero_aligned as u32,
            "spec0.next: bytes from spec0's own start to spec1"
        );
        assert_eq!(
            next1, linear_aligned as u32,
            "spec1.next: bytes from spec1's own start to spec2"
        );
        assert_eq!(next2, 0, "last spec's next must be 0");
        assert_eq!(b.count, 3);
    }

    /// Hand-builds a synthetic `DM_TABLE_STATUS`-shaped response buffer:
    /// header + N `dm_target_spec` entries whose `next` fields use the
    /// *read*-direction convention (offset from the *first* spec's start),
    /// each followed by a NUL-terminated status string. Deliberately
    /// independent of `TableBuilder` (the write-side builder), matching the
    /// old `synthetic_table_status_response` helper.
    fn synthetic_table_status_response(entries: &[(&[u8], &str)]) -> (Vec<u8>, u32) {
        let first = DmHeader::SIZE;
        let mut aligned_lens = Vec::with_capacity(entries.len());
        let mut payload_len = 0usize;
        for (_, params) in entries {
            let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
            aligned_lens.push(aligned);
            payload_len += aligned;
        }
        let mut bytes = vec![0u8; first + payload_len];

        let mut abs_offset_from_first = 0usize;
        for (i, (type_name, params)) in entries.iter().enumerate() {
            let abs_offset = first + abs_offset_from_first;
            let aligned_len = aligned_lens[i];
            let next = if i == entries.len() - 1 {
                0
            } else {
                (abs_offset_from_first + aligned_len) as u32
            };

            bytes[abs_offset..abs_offset + 8].copy_from_slice(&0u64.to_ne_bytes()); // sector_start
            bytes[abs_offset + 8..abs_offset + 16].copy_from_slice(&0u64.to_ne_bytes()); // length
            bytes[abs_offset + 20..abs_offset + 24].copy_from_slice(&next.to_ne_bytes());
            let type_field = &mut bytes[abs_offset + 24..abs_offset + 24 + DM_MAX_TYPE_NAME];
            type_field[..type_name.len()].copy_from_slice(type_name);

            let param_start = abs_offset + DM_TARGET_SPEC_SIZE;
            bytes[param_start..param_start + params.len()].copy_from_slice(params.as_bytes());

            abs_offset_from_first += aligned_len;
        }

        (bytes, entries.len() as u32)
    }

    #[test]
    fn spec_row_parses_matching_target_and_rejects_others() {
        let (bytes, count) = synthetic_table_status_response(&[(b"linear", "252:5 5")]);
        let row = TableStatusIter::<mode::Spec>::new(bytes, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.type_name(), "linear");
        assert_eq!(row.start(), 0);
        // Round-trips into a Linear...
        assert_eq!(
            row.parse::<Linear>(),
            Some(Linear {
                device: DevId::new(252, 5),
                offset_sectors: 5
            })
        );
        // ...but a type-name mismatch yields None, not a misparse. (Only
        // FromStr targets can be `parse`d on a Spec row, so this uses
        // snapshot::Origin — a different type name that would parse "252:5 5"
        // as garbage if the type-name guard weren't checked first.)
        assert_eq!(row.parse::<targets::snapshot::Origin>(), None);
    }

    #[test]
    fn spec_row_display_reconstructs_the_full_line() {
        let (bytes, count) = synthetic_table_status_response(&[(b"linear", "252:5 5")]);
        let row = TableStatusIter::<mode::Spec>::new(bytes, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.to_string(), "0 0 linear 252:5 5");

        let (empty, count) = synthetic_table_status_response(&[(b"zero", "")]);
        let row = TableStatusIter::<mode::Spec>::new(empty, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.to_string(), "0 0 zero");
    }

    #[test]
    fn table_status_iter_follows_next_relative_to_first_spec() {
        // Three entries with different-length status strings, so a parser
        // that treated `next` as relative to the *current* spec would land
        // on garbage instead of the real next entry.
        let (bytes, count) = synthetic_table_status_response(&[
            (b"zero", ""),
            (b"linear", "252:5 5"),
            (b"error", ""),
        ]);
        let rows: Vec<Row<mode::Spec>> =
            TableStatusIter::new(bytes, DmHeader::SIZE, count).collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].parse::<targets::Zero>(), Some(targets::Zero));
        assert_eq!(
            rows[1].parse::<Linear>(),
            Some(Linear {
                device: DevId::new(252, 5),
                offset_sectors: 5
            })
        );
        assert_eq!(rows[2].parse::<targets::Error>(), Some(targets::Error));
    }

    #[test]
    fn table_status_iter_stops_when_count_exceeds_available_specs() {
        // target_count claims 3 but the buffer holds only 1 spec: the bounds
        // guard must terminate cleanly instead of reading past the end.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let rows: Vec<Row<mode::Spec>> = TableStatusIter::new(bytes, DmHeader::SIZE, 3).collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].type_name(), "zero");
    }

    #[test]
    fn table_status_iter_next_zero_terminates_before_remaining_reaches_zero() {
        // A single real entry whose next==0, but remaining=2: the next==0
        // jump-to-end must win over the remaining counter.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let rows: Vec<Row<mode::Spec>> = TableStatusIter::new(bytes, DmHeader::SIZE, 2).collect();
        assert_eq!(rows.len(), 1);
    }

    // --- Mode/name safety ------------------------------------------------

    #[test]
    fn info_row_parse_of_non_matching_type_is_none() {
        // An info row reports runtime status, never a target's ctor params;
        // parsing it as a different target's Info must yield None on a
        // type-name mismatch (RawInfo's own FromStr is infallible, so the
        // guard is the type_name check).
        let (bytes, count) = synthetic_table_status_response(&[(b"raid", "raid1 2 AA 1.0 idle 0")]);
        let row = TableStatusIter::<mode::Info>::new(bytes, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.type_name(), "raid");
        // Matching type: RawInfo captures the raw status string.
        assert_eq!(
            row.parse::<targets::Raid>(),
            Some(RawInfo("raid1 2 AA 1.0 idle 0".to_owned()))
        );
        // Non-matching type: None.
        assert_eq!(row.parse::<Linear>(), None);
    }

    #[test]
    fn table_status_iter_truncates_a_long_type_name_at_the_nul() {
        // A full-width (unterminated) type field must be read as exactly
        // DM_MAX_TYPE_NAME bytes, never past the fixed field into params.
        let (mut bytes, count) = synthetic_table_status_response(&[(b"zero", "")]);
        let type_off = DmHeader::SIZE + 24;
        bytes[type_off..type_off + DM_MAX_TYPE_NAME].copy_from_slice(b"abcdefghijklmnop");
        let row = TableStatusIter::<mode::Spec>::new(bytes, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.type_name(), "abcdefghijklmnop");
        assert_eq!(row.type_name().len(), DM_MAX_TYPE_NAME);
    }

    // --- Builder NUL / type-name guards, and extensibility ---------------

    /// A local out-of-tree target whose `Display` writes an interior NUL —
    /// the builder must reject it rather than truncate the table line.
    struct NulTarget;
    impl Target for NulTarget {
        const TYPE_NAME: &'static str = "nul-target";
        type Info = RawInfo;
    }
    impl fmt::Display for NulTarget {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("before\0after")
        }
    }

    #[test]
    fn builder_rejects_an_interior_nul_in_params() {
        let r = TableBuilder::new(dummy_control(), DevId::new(252, 1)).add(0, 8, NulTarget);
        assert!(matches!(r, Err(Error::Usage(_))));
    }

    /// A target whose `TYPE_NAME` contains whitespace — invalid per the
    /// `Target` contract; the builder must reject it.
    struct BadNameTarget;
    impl Target for BadNameTarget {
        const TYPE_NAME: &'static str = "bad name";
        type Info = RawInfo;
    }
    impl fmt::Display for BadNameTarget {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    #[test]
    fn builder_rejects_an_invalid_type_name() {
        let r = TableBuilder::new(dummy_control(), DevId::new(252, 1)).add(0, 8, BadNameTarget);
        assert!(matches!(r, Err(Error::Usage(_))));
    }

    /// A well-formed out-of-tree target for a made-up type name — proving a
    /// caller can define and `add` their own `Target` implementation.
    struct CustomTarget {
        value: u32,
    }
    impl Target for CustomTarget {
        const TYPE_NAME: &'static str = "custom-target";
        type Info = RawInfo;
    }
    impl fmt::Display for CustomTarget {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "1 2 {}", self.value)
        }
    }
    impl FromStr for CustomTarget {
        type Err = ParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let value = s
                .strip_prefix("1 2 ")
                .ok_or(ParseError)?
                .parse()
                .map_err(|_| ParseError)?;
            Ok(CustomTarget { value })
        }
    }

    #[test]
    fn an_out_of_tree_target_can_be_added_and_parsed() {
        // Extensibility proof: a user-defined Target renders into the builder
        // and round-trips through a synthetic Spec row.
        let b = TableBuilder::new(dummy_control(), DevId::new(252, 1))
            .add(0, 8, CustomTarget { value: 3 })
            .expect("add custom target");
        assert_eq!(b.rendered, ["0 8 custom-target 1 2 3"]);

        let (bytes, count) = synthetic_table_status_response(&[(b"custom-target", "1 2 3")]);
        let row = TableStatusIter::<mode::Spec>::new(bytes, DmHeader::SIZE, count)
            .next()
            .expect("one row");
        assert_eq!(row.parse::<CustomTarget>().map(|t| t.value), Some(3));
    }

    struct EmptyName;
    impl Target for EmptyName {
        const TYPE_NAME: &'static str = "";
        type Info = RawInfo;
    }
    impl fmt::Display for EmptyName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }
    // 16 bytes == DM_MAX_TYPE_NAME: no room for the NUL terminator, so rejected.
    struct SixteenByteName;
    impl Target for SixteenByteName {
        const TYPE_NAME: &'static str = "0123456789abcdef";
        type Info = RawInfo;
    }
    impl fmt::Display for SixteenByteName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }
    // 15 bytes: the longest name that fits with a NUL terminator.
    struct FifteenByteName;
    impl Target for FifteenByteName {
        const TYPE_NAME: &'static str = "0123456789abcde";
        type Info = RawInfo;
    }
    impl fmt::Display for FifteenByteName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    #[test]
    fn builder_rejects_empty_and_overlong_type_names_but_accepts_15_bytes() {
        let dev = DevId::new(252, 1);
        assert!(matches!(
            TableBuilder::new(dummy_control(), dev).add(0, 8, EmptyName),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            TableBuilder::new(dummy_control(), dev).add(0, 8, SixteenByteName),
            Err(Error::Usage(_))
        ));
        assert!(
            TableBuilder::new(dummy_control(), dev)
                .add(0, 8, FifteenByteName)
                .is_ok()
        );
    }

    #[test]
    fn table_status_iter_terminates_on_offset_overflow() {
        // A kernel-reported base offset near usize::MAX makes the per-spec
        // `checked_add` overflow; the iterator must stop, not panic.
        let buf = vec![0u8; DmHeader::SIZE];
        let mut it = TableStatusIter::<mode::Spec>::new(buf, usize::MAX - 1, 1);
        assert!(it.next().is_none());
    }
}
