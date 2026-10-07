// SPDX-License-Identifier: Apache-2.0

//! Rows returned while inspecting a device-mapper table.
//!
//! The kernel reports each target as a [`Row`]: [`Table`] rows contain
//! construction parameters, while [`Info`] rows contain runtime information.
//! Use [`Row::parse`] with a target type to interpret either response.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::marker::PhantomData;

use crate::uapi::{DM_MAX_TYPE_NAME, DM_TARGET_SPEC_SIZE};

use crate::target::{Parse, Target, Version};

#[cfg(test)]
use crate::header::DmHeader;

/// `STATUSTYPE_TABLE`: the mapping's construction parameters.
#[derive(Debug)]
pub enum Table {}

/// `STATUSTYPE_INFO`: per-target runtime status.
#[derive(Debug)]
pub enum Info {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Table {}
    impl Sealed for super::Info {}
}

/// Sealed marker distinguishing the two `DM_TABLE_STATUS` payloads.
pub trait Mode: sealed::Sealed {}
impl Mode for Table {}
impl Mode for Info {}

/// A target's sector range and kernel response, returned by
/// [`Device::table`](crate::device::Device::table) or
/// [`Device::info`](crate::device::Device::info).
///
/// Call [`parse`](Row::parse) with the expected [`Target`] type. A table row
/// yields `T::Table`; an info row yields `T::Info`. A different target name
/// produces `InvalidInput`; an undecodable response produces `InvalidData`.
/// The kernel target version is supplied to the target's parser automatically.
/// Raw response parameters are not exposed; `Debug` redacts them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Row<M: Mode> {
    start: u64,
    length: u64,
    type_name: String,
    params: String,
    version: Version,
    _mode: PhantomData<M>,
}

impl<M: Mode> fmt::Debug for Row<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Row")
            .field("start", &self.start)
            .field("length", &self.length)
            .field("type_name", &self.type_name)
            .field("version", &self.version)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl<M: Mode> Row<M> {
    /// First sector covered by this row.
    pub fn start(&self) -> u64 {
        self.start
    }
    /// Number of sectors covered by this row.
    pub fn length(&self) -> u64 {
        self.length
    }

    fn check_target<T: Target>(&self) -> io::Result<()> {
        if self.type_name == T::NAME {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected target {}, found {}", T::NAME, self.type_name),
            ))
        }
    }
}

impl Row<Table> {
    /// Read this table row as target `T`'s table type ([`Target::Table`]).
    ///
    /// Returns `InvalidInput` for a different target name or `InvalidData`
    /// when the target cannot parse the reported parameters or version.
    pub fn parse<T: Target>(&self) -> io::Result<T::Table> {
        self.check_target::<T>()?;
        <T::Table as Parse<Table>>::parse(&self.params, self.version)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl Row<Info> {
    /// Parse this status row as target `T`'s runtime status ([`Target::Info`]).
    ///
    /// Returns `InvalidInput` for a different target name or `InvalidData`
    /// when the target cannot parse the reported status or version.
    pub fn parse<T: Target>(&self) -> io::Result<T::Info> {
        self.check_target::<T>()?;
        <T::Info as Parse<Info>>::parse(&self.params, self.version)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

/// Parses a `DM_TABLE_STATUS` response into raw rows. The device resolves
/// each target version before exposing public [`Row`]s.
///
/// `dm_target_spec.next` here is the byte offset from the *first* spec's
/// start to the next one (the read-direction convention, opposite the
/// write side — see `<linux/dm-ioctl.h>`).
pub(crate) struct TableStatusIter<M: Mode> {
    buf: Vec<u8>,
    first: usize,
    offset: usize,
    remaining: u32,
    _mode: PhantomData<M>,
}

impl<M: Mode> TableStatusIter<M> {
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

impl<M: Mode> Iterator for TableStatusIter<M> {
    type Item = RawRow<M>;

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

        Some(RawRow {
            start: sector_start,
            length,
            type_name,
            params,
            _mode: PhantomData,
        })
    }
}

/// A parsed status row before the target version has been resolved.
pub(crate) struct RawRow<M: Mode> {
    start: u64,
    length: u64,
    type_name: String,
    params: String,
    _mode: PhantomData<M>,
}

impl<M: Mode> RawRow<M> {
    pub(crate) fn type_name(&self) -> &str {
        &self.type_name
    }

    pub(crate) fn with_version(self, version: Version) -> Row<M> {
        Row {
            start: self.start,
            length: self.length,
            type_name: self.type_name,
            params: self.params,
            version,
            _mode: PhantomData,
        }
    }
}

/// Resolve each distinct target type once before exposing typed rows.
pub(crate) fn version_rows<M: Mode>(
    raw: impl IntoIterator<Item = RawRow<M>>,
    mut query: impl FnMut(&str) -> io::Result<Version>,
) -> io::Result<Vec<Row<M>>> {
    let mut versions = HashMap::new();
    let mut rows = Vec::new();

    for row in raw {
        let name = row.type_name();
        let version = if let Some(version) = versions.get(name) {
            *version
        } else {
            let version = query(name)?;
            versions.insert(name.to_owned(), version);
            version
        };
        rows.push(row.with_version(version));
    }

    Ok(rows)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures: sizes are tiny, never near u32::MAX
mod tests {
    use super::*;
    use crate::ParseError as Error;
    use crate::target::crypt::CryptTarget;

    fn status_rows<M: Mode>(bytes: Vec<u8>, count: u32) -> Vec<Row<M>> {
        TableStatusIter::<M>::new(bytes, DmHeader::SIZE, count)
            .map(|row| row.with_version(Version::from([1, 0, 0])))
            .collect()
    }

    #[test]
    fn status_rows_resolve_each_target_name_once() {
        let (bytes, count) = synthetic_table_status_response(&[
            (b"zero", ""),
            (b"linear", "252:1 0"),
            (b"zero", ""),
        ]);
        let raw = TableStatusIter::<Table>::new(bytes, DmHeader::SIZE, count);
        let mut names = Vec::new();
        let rows = version_rows(raw, |name| {
            names.push(name.to_owned());
            Ok(Version::from([1, 2, 3]))
        })
        .unwrap();

        assert_eq!(names, ["zero", "linear"]);
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter()
                .all(|row| row.version == Version::from([1, 2, 3]))
        );
    }

    #[test]
    fn status_rows_propagate_version_lookup_failure() {
        let (bytes, count) = synthetic_table_status_response(&[(b"zero", "")]);
        let raw = TableStatusIter::<Info>::new(bytes, DmHeader::SIZE, count);
        let result = version_rows(raw, |_| Err(io::Error::other("lookup failed")));
        assert!(matches!(result, Err(error) if error.to_string() == "lookup failed"));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Dual(u32);

    impl Parse<Table> for Dual {
        type Error = Error;

        fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
            if version.major != 1 {
                return Err(Error);
            }
            Ok(Self(text.strip_prefix("spec ").ok_or(Error)?.parse()?))
        }
    }

    impl Parse<Info> for Dual {
        type Error = Error;

        fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
            if version.major != 1 {
                return Err(Error);
            }
            Ok(Self(text.strip_prefix("info ").ok_or(Error)?.parse()?))
        }
    }

    struct DualTarget;

    impl Target for DualTarget {
        const NAME: &'static str = "dual";
        type Table = Dual;
        type Info = Dual;

        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }

    #[test]
    fn row_parse_dispatches_by_mode_and_version() {
        let (bytes, count) = synthetic_table_status_response(&[(b"dual", "spec 7")]);
        let raw = TableStatusIter::<Table>::new(bytes, DmHeader::SIZE, count)
            .next()
            .unwrap();
        let row = raw.with_version(Version::from([1, 0, 0]));
        assert_eq!(row.parse::<DualTarget>().unwrap(), Dual(7));

        let (bytes, count) = synthetic_table_status_response(&[(b"dual", "info 9")]);
        let raw = TableStatusIter::<Info>::new(bytes, DmHeader::SIZE, count)
            .next()
            .unwrap();
        let row = raw.with_version(Version::from([1, 0, 0]));
        assert_eq!(row.parse::<DualTarget>().unwrap(), Dual(9));

        let (bytes, count) = synthetic_table_status_response(&[(b"dual", "spec 7")]);
        let raw = TableStatusIter::<Table>::new(bytes, DmHeader::SIZE, count)
            .next()
            .unwrap();
        assert_eq!(
            raw.with_version(Version::from([2, 0, 0]))
                .parse::<DualTarget>()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// Hand-builds a synthetic `DM_TABLE_STATUS`-shaped response buffer:
    /// header + N `dm_target_spec` entries whose `next` fields use the
    /// *read*-direction convention (offset from the *first* spec's start),
    /// each followed by a NUL-terminated status string.
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
        let params = "aes-xts-plain64 - 0 252:5 5";
        let (bytes, count) = synthetic_table_status_response(&[(b"crypt", params)]);
        let mut row = status_rows::<Table>(bytes, count).remove(0);
        row.version = Version::from([1, 29, 0]);
        assert_eq!(row.start(), 0);
        assert_eq!(row.parse::<CryptTarget>().unwrap(), params.parse().unwrap());
        assert_eq!(
            row.parse::<crate::target::zero::ZeroTarget>()
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn malformed_row_preserves_the_parser_error() {
        let (bytes, count) = synthetic_table_status_response(&[(b"crypt", "invalid")]);
        let row = status_rows::<Table>(bytes, count).remove(0);
        let error = row.parse::<CryptTarget>().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.get_ref().unwrap().downcast_ref::<Error>().is_some());
    }

    #[test]
    fn row_debug_redacts_parameters() {
        let (bytes, count) = synthetic_table_status_response(&[(b"crypt", "secret-key")]);
        let row = status_rows::<Table>(bytes, count).remove(0);
        let debug = format!("{row:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-key"));
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
        let rows = status_rows::<Table>(bytes, count);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[0].parse::<crate::target::zero::ZeroTarget>().unwrap(),
            crate::target::zero::ZeroTarget
        );
        assert_eq!(rows[1].type_name, "linear");
        assert_eq!(rows[1].params, "252:5 5");
        assert_eq!(rows[2].type_name, "error");
        assert_eq!(rows[2].params, "");
    }

    #[test]
    fn table_status_iter_stops_when_count_exceeds_available_specs() {
        // target_count claims 3 but the buffer holds only 1 spec: the bounds
        // guard must terminate cleanly instead of reading past the end.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let rows = status_rows::<Table>(bytes, 3);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].type_name, "zero");
    }

    #[test]
    fn table_status_iter_next_zero_terminates_before_remaining_reaches_zero() {
        // A single real entry whose next==0, but remaining=2: the next==0
        // jump-to-end must win over the remaining counter.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let rows = status_rows::<Table>(bytes, 2);
        assert_eq!(rows.len(), 1);
    }

    // --- Mode/name safety ------------------------------------------------

    #[test]
    fn table_status_iter_truncates_a_long_type_name_at_the_nul() {
        // A full-width (unterminated) type field must be read as exactly
        // DM_MAX_TYPE_NAME bytes, never past the fixed field into params.
        let (mut bytes, count) = synthetic_table_status_response(&[(b"zero", "")]);
        let type_off = DmHeader::SIZE + 24;
        bytes[type_off..type_off + DM_MAX_TYPE_NAME].copy_from_slice(b"abcdefghijklmnop");
        let row = status_rows::<Table>(bytes, count).remove(0);
        assert_eq!(row.type_name, "abcdefghijklmnop");
        assert_eq!(row.type_name.len(), DM_MAX_TYPE_NAME);
    }

    #[test]
    fn table_status_iter_terminates_on_offset_overflow() {
        // A kernel-reported base offset near usize::MAX makes the per-spec
        // `checked_add` overflow; the iterator must stop, not panic.
        let buf = vec![0u8; DmHeader::SIZE];
        let mut it = TableStatusIter::<Table>::new(buf, usize::MAX - 1, 1);
        assert!(it.next().is_none());
    }
}
