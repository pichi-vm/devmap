// SPDX-License-Identifier: Apache-2.0

//! Build device-mapper tables and read their target rows.
//!
//! [`TableBuilder`] loads targets implementing [`Target`]. The kernel later
//! reports each target as a [`Row`]: [`TableMode`] rows contain construction
//! parameters, while [`InfoMode`] rows contain runtime status. Use
//! [`Row::parse`] with a target type to interpret either response.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::marker::PhantomData;

#[cfg(test)]
use std::str::FromStr;
use std::sync::Arc;

use zerocopy::{FromBytes, IntoBytes};

use crate::control::target_version;
use crate::device::check_version;
use crate::header::DmHeader;
use crate::uapi::{DM_MAX_TYPE_NAME, DM_TABLE_LOAD, DM_TARGET_SPEC_SIZE, dm_target_spec_raw};

use crate::DevId;
use crate::target::{Parse, Target, Version};

/// `STATUSTYPE_TABLE`: the mapping's construction parameters.
#[derive(Debug)]
pub enum TableMode {}

/// `STATUSTYPE_INFO`: per-target runtime status.
#[derive(Debug)]
pub enum InfoMode {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::TableMode {}
    impl Sealed for super::InfoMode {}
}

/// Sealed marker distinguishing the two `DM_TABLE_STATUS` payloads.
pub trait Mode: sealed::Sealed {}
impl Mode for TableMode {}
impl Mode for InfoMode {}

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

impl Row<TableMode> {
    /// Read this table row as target `T`'s table type ([`Target::Table`]).
    ///
    /// Returns `InvalidInput` for a different target name or `InvalidData`
    /// when the target cannot parse the reported parameters or version.
    pub fn parse<T: Target>(&self) -> io::Result<T::Table> {
        self.check_target::<T>()?;
        <T::Table as Parse<TableMode>>::parse(&self.params, self.version)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl Row<InfoMode> {
    /// Parse this status row as target `T`'s runtime status ([`Target::Info`]).
    ///
    /// Returns `InvalidInput` for a different target name or `InvalidData`
    /// when the target cannot parse the reported status or version.
    pub fn parse<T: Target>(&self) -> io::Result<T::Info> {
        self.check_target::<T>()?;
        <T::Info as Parse<InfoMode>>::parse(&self.params, self.version)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

/// A streaming builder for `DM_TABLE_LOAD`: each [`add`](TableBuilder::add)
/// renders a target directly into one growing buffer. Terminate with
/// [`load`](TableBuilder::load). Obtained from [`crate::device::Device::builder`].
#[derive(Debug)]
pub struct TableBuilder {
    control: Arc<File>,
    versions: HashMap<String, Version>,
    buf: Vec<u8>,
    count: u32,
    last_spec_off: Option<usize>,
}

impl TableBuilder {
    pub(crate) fn new(control: Arc<File>, dev: DevId) -> Self {
        let mut buf = Vec::with_capacity(DmHeader::SIZE + 256);
        buf.extend_from_slice(DmHeader::by_dev(u64::from(dev)).as_bytes());
        Self {
            control,
            versions: HashMap::new(),
            buf,
            count: 0,
            last_spec_off: None,
        }
    }

    /// Load the table **read-only** (sets `DM_READONLY_FLAG` on the
    /// `DM_TABLE_LOAD` header, which sets the table's mode). Required for
    /// dm-verity — it refuses a writable table with `-EINVAL` "Device must be
    /// readonly" — and used for read-only dm-snapshot composition. Call any
    /// time before [`load`](Self::load).
    // The `mut_from_prefix` expect never fires: the buffer always begins with
    // a `DmHeader` (written in `new`).
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn read_only(mut self) -> Self {
        let (header, _) =
            DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
        let header: &mut DmHeader = header;
        header.set_readonly();
        self
    }

    /// Append a target mapping sectors `[start, start + length)`.
    ///
    /// # Errors
    ///
    /// `Unsupported` if the target cannot encode the installed version; `InvalidInput`
    /// if `T::NAME` is invalid or the encoded params contain an interior NUL.
    // Table buffers never approach u32::MAX; the kernel's own fields are u32.
    // `target` is taken by value: the builder consumes its encoded row.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add<T: Target>(mut self, start: u64, length: u64, target: T) -> io::Result<Self> {
        Self::check_name(T::NAME)?;
        let version = self.resolve_version(T::NAME, target_version)?;
        let params = target.encode(version).map_err(|error| {
            io::Error::new(io::ErrorKind::Unsupported, format!("{}: {error}", T::NAME))
        })?;
        self.push_row(start, length, T::NAME, &params)
    }

    fn resolve_version(
        &mut self,
        name: &str,
        query: impl FnOnce(&File, &str) -> io::Result<Version>,
    ) -> io::Result<Version> {
        if let Some(version) = self.versions.get(name) {
            return Ok(*version);
        }
        let version = query(&self.control, name)?;
        self.versions.insert(name.to_owned(), version);
        Ok(version)
    }

    fn check_name(type_name: &str) -> io::Result<()> {
        let name = type_name.as_bytes();
        if name.is_empty()
            || name.len() >= DM_MAX_TYPE_NAME
            || name.iter().any(|b| *b == 0 || b.is_ascii_whitespace())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid dm target type name: {type_name:?}"),
            ));
        }
        Ok(())
    }

    /// Append a validated target row to the ioctl buffer.
    // Table buffers never approach u32::MAX; the kernel's own fields are u32.
    #[allow(clippy::cast_possible_truncation)]
    fn push_row(
        mut self,
        start: u64,
        length: u64,
        type_name: &str,
        params: &str,
    ) -> io::Result<Self> {
        Self::check_name(type_name)?;
        let name = type_name.as_bytes();
        if params.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("target {type_name} params contain an interior NUL"),
            ));
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

        self.last_spec_off = Some(spec_off);
        self.count += 1;
        Ok(self)
    }

    /// Issue `DM_TABLE_LOAD`, staging the accumulated table into the
    /// device's inactive slot. Activate with [`crate::device::Device::resume`].
    // The `mut_from_prefix` expects never fire: the buffer always begins with
    // a `DmHeader` (written in `new`), so this is not a real panic path.
    #[allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]
    pub fn load(mut self) -> io::Result<()> {
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
        DM_TABLE_LOAD.ioctl(&*self.control, header)?;
        check_version(header)
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

    /// An `Arc<File>` for a `TableBuilder` that never issues a real ioctl:
    /// the rendering/validation paths run entirely before `load`.
    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    fn builder(dev: DevId) -> TableBuilder {
        let mut builder = TableBuilder::new(dummy_control(), dev);
        let version = Version::from([1, 0, 0]);
        for name in ["zero", "nul-target", "custom-target", "0123456789abcde"] {
            builder.versions.insert(name.to_owned(), version);
        }
        builder
    }

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
        let raw = TableStatusIter::<TableMode>::new(bytes, DmHeader::SIZE, count);
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
        let raw = TableStatusIter::<InfoMode>::new(bytes, DmHeader::SIZE, count);
        let result = version_rows(raw, |_| Err(io::Error::other("lookup failed")));
        assert!(matches!(result, Err(error) if error.to_string() == "lookup failed"));
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Dual(u32);

    impl Parse<TableMode> for Dual {
        type Error = Error;

        fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
            if version.major != 1 {
                return Err(Error);
            }
            Ok(Self(text.strip_prefix("spec ").ok_or(Error)?.parse()?))
        }
    }

    impl Parse<InfoMode> for Dual {
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
        let raw = TableStatusIter::<TableMode>::new(bytes, DmHeader::SIZE, count)
            .next()
            .unwrap();
        let row = raw.with_version(Version::from([1, 0, 0]));
        assert_eq!(row.parse::<DualTarget>().unwrap(), Dual(7));

        let (bytes, count) = synthetic_table_status_response(&[(b"dual", "info 9")]);
        let raw = TableStatusIter::<InfoMode>::new(bytes, DmHeader::SIZE, count)
            .next()
            .unwrap();
        let row = raw.with_version(Version::from([1, 0, 0]));
        assert_eq!(row.parse::<DualTarget>().unwrap(), Dual(9));

        let (bytes, count) = synthetic_table_status_response(&[(b"dual", "spec 7")]);
        let raw = TableStatusIter::<TableMode>::new(bytes, DmHeader::SIZE, count)
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

    #[test]
    fn version_lookup_is_cached_by_target_name() {
        let mut builder = TableBuilder::new(dummy_control(), DevId::new(252, 1).unwrap());
        let expected = Version::from([1, 2, 3]);
        assert_eq!(
            builder
                .resolve_version("zero", |_, _| Ok(expected))
                .unwrap(),
            expected
        );
        assert_eq!(
            builder
                .resolve_version("zero", |_, _| panic!("second lookup must use cache"))
                .unwrap(),
            expected
        );
        assert_eq!(builder.versions.len(), 1);
    }

    #[test]
    fn unsupported_target_version_is_rejected() {
        let mut builder = builder(DevId::new(252, 1).unwrap());
        builder
            .versions
            .insert("zero".to_owned(), Version::from([2, 0, 0]));
        let result = builder.add(0, 8, crate::target::zero::ZeroTarget);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported));
    }

    // --- Builder buffer layout -------------------------------------------
    //
    // `mod tests` is inside the `table` module, so it reads `TableBuilder`'s
    // private `buf` directly — no public accessor is added to the lib. This
    // ports the old `DmTableBuf::build` byte-layout spot checks.

    #[test]
    fn buf_for_zero_target_has_correct_layout() {
        let b = builder(DevId::new(252, 5).unwrap())
            .add(0, 8, crate::target::zero::ZeroTarget)
            .expect("add zero");
        // header + (40 spec + 0 params + 1 NUL = 41 -> padded to 48).
        assert_eq!(b.buf.len(), DmHeader::SIZE + 48);
    }

    #[test]
    fn read_only_sets_the_readonly_flag_on_the_header() {
        use zerocopy::FromBytes as _;
        let b = builder(DevId::new(252, 5).unwrap())
            .read_only()
            .add(0, 8, crate::target::zero::ZeroTarget)
            .expect("add zero");
        let (header, _) = DmHeader::ref_from_prefix(&b.buf).expect("buf begins with a DmHeader");
        let header: &DmHeader = header;
        assert_eq!(
            header.flags() & crate::uapi::DM_READONLY_FLAG,
            crate::uapi::DM_READONLY_FLAG,
            "read_only() must set DM_READONLY_FLAG"
        );
    }

    #[test]
    fn default_builder_does_not_set_readonly() {
        use zerocopy::FromBytes as _;
        let b = builder(DevId::new(252, 5).unwrap())
            .add(0, 8, crate::target::zero::ZeroTarget)
            .expect("add zero");
        let (header, _) = DmHeader::ref_from_prefix(&b.buf).expect("buf begins with a DmHeader");
        let header: &DmHeader = header;
        assert_eq!(header.flags() & crate::uapi::DM_READONLY_FLAG, 0);
    }

    #[test]
    fn buf_for_linear_target_has_correct_layout_and_params() {
        let b = builder(DevId::new(252, 9).unwrap())
            .push_row(0, 1024, "linear", "252:5 0")
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
    fn buf_for_three_target_table_chains_specs_with_offsets_relative_to_current() {
        // Write-side `next` is relative to *each spec's own* start (unlike
        // the read side). Three lines, not two: with only two, the first
        // spec's `next` can't distinguish "relative to current" from
        // "relative to first".
        let b = builder(DevId::new(252, 9).unwrap())
            .add(0, 8, crate::target::zero::ZeroTarget)
            .and_then(|b| b.push_row(8, 1024, "linear", "252:5 5"))
            .and_then(|b| b.push_row(1032, 8, "error", ""))
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
        let params = "aes-xts-plain64 - 0 252:5 5";
        let (bytes, count) = synthetic_table_status_response(&[(b"crypt", params)]);
        let mut row = status_rows::<TableMode>(bytes, count).remove(0);
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
        let row = status_rows::<TableMode>(bytes, count).remove(0);
        let error = row.parse::<CryptTarget>().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.get_ref().unwrap().downcast_ref::<Error>().is_some());
    }

    #[test]
    fn row_debug_redacts_parameters() {
        let (bytes, count) = synthetic_table_status_response(&[(b"crypt", "secret-key")]);
        let row = status_rows::<TableMode>(bytes, count).remove(0);
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
        let rows = status_rows::<TableMode>(bytes, count);
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
        let rows = status_rows::<TableMode>(bytes, 3);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].type_name, "zero");
    }

    #[test]
    fn table_status_iter_next_zero_terminates_before_remaining_reaches_zero() {
        // A single real entry whose next==0, but remaining=2: the next==0
        // jump-to-end must win over the remaining counter.
        let (bytes, _) = synthetic_table_status_response(&[(b"zero", "")]);
        let rows = status_rows::<TableMode>(bytes, 2);
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
        let row = status_rows::<TableMode>(bytes, count).remove(0);
        assert_eq!(row.type_name, "abcdefghijklmnop");
        assert_eq!(row.type_name.len(), DM_MAX_TYPE_NAME);
    }

    // --- Builder NUL / type-name guards, and extensibility ---------------

    /// The table type of a fixture that is never read back. These exist to
    /// prove the builder rejects malformed targets, so all but one are
    /// turned away by `add` before any ioctl and none reaches a kernel —
    /// there is no status string for them to interpret. Parsing one means
    /// a test asked for something that can't happen, so this always fails
    /// rather than inventing a value.
    #[derive(Debug)]
    struct Unreadable;
    impl FromStr for Unreadable {
        type Err = Error;
        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Err(Error)
        }
    }

    impl Parse<TableMode> for Unreadable {
        type Error = Error;

        fn parse(_: &str, _: Version) -> Result<Self, Self::Error> {
            Err(Error)
        }
    }

    /// A local out-of-tree target whose encoder writes an interior NUL —
    /// the builder must reject it rather than truncate the table line.
    struct NulTarget;
    impl Target for NulTarget {
        const NAME: &'static str = "nul-target";
        type Table = Unreadable;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok("before\0after".to_owned())
        }
    }
    impl fmt::Display for NulTarget {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("before\0after")
        }
    }

    #[test]
    fn builder_rejects_an_interior_nul_in_params() {
        let r = builder(DevId::new(252, 1).unwrap()).add(0, 8, NulTarget);
        assert!(matches!(r, Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    /// A target whose `NAME` contains whitespace — invalid per the
    /// `Target` contract; the builder must reject it.
    struct BadNameTarget;
    impl Target for BadNameTarget {
        const NAME: &'static str = "bad name";
        type Table = Unreadable;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }
    impl fmt::Display for BadNameTarget {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    #[test]
    fn builder_rejects_an_invalid_type_name() {
        let r = builder(DevId::new(252, 1).unwrap()).add(0, 8, BadNameTarget);
        assert!(matches!(r, Err(e) if e.kind() == io::ErrorKind::InvalidInput));
    }

    /// A well-formed out-of-tree target for a made-up type name — proving a
    /// caller can define and `add` their own `Target` implementation.
    struct CustomTarget {
        value: u32,
    }
    impl Target for CustomTarget {
        const NAME: &'static str = "custom-target";
        type Table = Self;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(self.to_string())
        }
    }
    impl fmt::Display for CustomTarget {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "1 2 {}", self.value)
        }
    }
    impl FromStr for CustomTarget {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let value = s
                .strip_prefix("1 2 ")
                .ok_or(Error)?
                .parse()
                .map_err(|_| Error)?;
            Ok(CustomTarget { value })
        }
    }

    impl Parse<TableMode> for CustomTarget {
        type Error = Error;

        fn parse(text: &str, _: Version) -> Result<Self, Self::Error> {
            text.parse()
        }
    }

    #[test]
    fn an_out_of_tree_target_can_be_added_and_parsed() {
        // Extensibility proof: a user-defined Target renders into the builder
        // and round-trips through a synthetic table row.
        let b = builder(DevId::new(252, 1).unwrap())
            .add(0, 8, CustomTarget { value: 3 })
            .expect("add custom target");
        // Assert on the bytes bound for the kernel: the type name lands in
        // the spec's target_type field and the params follow it, NUL-
        // terminated.
        let params = "1 2 3";
        let type_field = &b.buf[DmHeader::SIZE + 24..DmHeader::SIZE + 24 + DM_MAX_TYPE_NAME];
        assert_eq!(&type_field[..CustomTarget::NAME.len()], b"custom-target");
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(
            &b.buf[param_start..param_start + params.len()],
            params.as_bytes()
        );
        assert_eq!(b.buf[param_start + params.len()], 0);

        let (bytes, count) = synthetic_table_status_response(&[(b"custom-target", "1 2 3")]);
        let row = status_rows::<TableMode>(bytes, count).remove(0);
        assert_eq!(row.parse::<CustomTarget>().unwrap().value, 3);
    }

    struct EmptyName;
    impl Target for EmptyName {
        const NAME: &'static str = "";
        type Table = Unreadable;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }
    impl fmt::Display for EmptyName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }
    // 16 bytes == DM_MAX_TYPE_NAME: no room for the NUL terminator, so rejected.
    struct SixteenByteName;
    impl Target for SixteenByteName {
        const NAME: &'static str = "0123456789abcdef";
        type Table = Unreadable;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }
    impl fmt::Display for SixteenByteName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }
    // 15 bytes: the longest name that fits with a NUL terminator.
    struct FifteenByteName;
    impl Target for FifteenByteName {
        const NAME: &'static str = "0123456789abcde";
        type Table = Unreadable;
        type Info = String;
        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }
    impl fmt::Display for FifteenByteName {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    #[test]
    fn builder_rejects_empty_and_overlong_type_names_but_accepts_15_bytes() {
        let dev = DevId::new(252, 1).unwrap();
        assert!(matches!(
            builder(dev).add(0, 8, EmptyName),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(matches!(
            builder(dev).add(0, 8, SixteenByteName),
            Err(e) if e.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(builder(dev).add(0, 8, FifteenByteName).is_ok());
    }

    #[test]
    fn table_status_iter_terminates_on_offset_overflow() {
        // A kernel-reported base offset near usize::MAX makes the per-spec
        // `checked_add` overflow; the iterator must stop, not panic.
        let buf = vec![0u8; DmHeader::SIZE];
        let mut it = TableStatusIter::<TableMode>::new(buf, usize::MAX - 1, 1);
        assert!(it.next().is_none());
    }
}
