// SPDX-License-Identifier: Apache-2.0

//! Device-mapper responses and their rows.
//!
//! A [`Response<Table>`] contains the active table's construction parameters;
//! a [`Response<Info>`] contains its runtime information. Responses own the
//! kernel buffer and lazily yield borrowed [`Row`] values.

mod mode;
mod row;

pub use mode::{Info, Mode, Table};
pub use row::Row;

use std::fmt;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Arc;

use devmap_core::Span;

use crate::header::DmHeader;
use crate::uapi::{DM_MAX_TYPE_NAME, DM_TARGET_SPEC_SIZE};

/// An owned device-mapper table response in mode `M`.
///
/// The response retains the kernel buffer. [`Response::rows`] decodes rows
/// lazily without allocating another collection or copying target parameters.
pub struct Response<M> {
    buffer: Vec<u8>,
    payload: Range<usize>,
    target_count: u32,
    control: Arc<File>,
    _mode: PhantomData<M>,
}

impl<M> Response<M> {
    pub(crate) fn new(buffer: Vec<u8>, control: Arc<File>) -> io::Result<Self> {
        let header = DmHeader::response(&buffer)?;
        let start = (header.data_start() as usize).min(buffer.len());
        let end = (header.data_size() as usize).min(buffer.len());
        if start > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dm table payload starts after its end",
            ));
        }
        Ok(Self {
            payload: start..end,
            target_count: header.target_count(),
            buffer,
            control,
            _mode: PhantomData,
        })
    }

    /// Lazily decode the response's target rows.
    ///
    /// A structurally malformed row is returned as `InvalidData`; iteration
    /// ends after that error.
    pub fn rows(&self) -> impl Iterator<Item = io::Result<Row<'_, M>>> {
        let base = self.payload.start;
        let end = self.payload.end;
        let mut offset = base;
        let mut remaining = self.target_count;

        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }

            let Some(spec_end) = offset.checked_add(DM_TARGET_SPEC_SIZE) else {
                remaining = 0;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "dm target spec offset overflow",
                )));
            };
            if spec_end > end {
                remaining = 0;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated dm target spec",
                )));
            }
            let spec = &self.buffer[offset..spec_end];
            let (Some(start), Some(length), Some(next)) = (
                spec.get(0..8).and_then(|bytes| bytes.try_into().ok()),
                spec.get(8..16).and_then(|bytes| bytes.try_into().ok()),
                spec.get(20..24).and_then(|bytes| bytes.try_into().ok()),
            ) else {
                remaining = 0;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid dm target spec layout",
                )));
            };
            let start = u64::from_ne_bytes(start);
            let length = u64::from_ne_bytes(length);
            let next = u32::from_ne_bytes(next);

            let record_end = if next == 0 {
                end
            } else {
                let Some(next_offset) = base.checked_add(next as usize) else {
                    remaining = 0;
                    return Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dm target next offset overflow",
                    )));
                };
                if next_offset < spec_end || next_offset > end {
                    remaining = 0;
                    return Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dm target next offset outside response",
                    )));
                }
                next_offset
            };

            let Some(type_field) = spec.get(24..24 + DM_MAX_TYPE_NAME) else {
                remaining = 0;
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid dm target type field",
                )));
            };
            let type_end = type_field
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(type_field.len());
            let type_name = match std::str::from_utf8(&type_field[..type_end]) {
                Ok(name) => name,
                Err(error) => {
                    remaining = 0;
                    return Some(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
                }
            };

            let params = &self.buffer[spec_end..record_end];
            let params_end = params
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(params.len());

            remaining -= 1;
            if next == 0 {
                remaining = 0;
            } else {
                offset = record_end;
            }

            Some(Ok(Row {
                span: Span::new(start, length),
                type_name,
                params: &params[..params_end],
                control: &self.control,
                _mode: PhantomData,
            }))
        })
    }
}

impl<M> fmt::Debug for Response<M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Response")
            .field("target_count", &self.target_count)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures: sizes are tiny, never near u32::MAX
mod tests {
    use super::*;
    use crate::response::Table;
    use zerocopy::{FromBytes as _, IntoBytes as _};

    /// Hand-builds a synthetic `DM_TABLE_STATUS`-shaped response buffer:
    /// header + N `dm_target_spec` entries whose `next` fields use the
    /// *read*-direction convention (offset from the *first* spec's start),
    /// each followed by a NUL-terminated status string.
    fn synthetic_table_status_response(entries: &[(&[u8], &str)]) -> Vec<u8> {
        let first = DmHeader::SIZE;
        let payload_len = entries
            .iter()
            .map(|(_, params)| (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8))
            .sum::<usize>();
        let mut bytes = vec![0u8; first + payload_len];
        let mut header = DmHeader::by_dev(0);
        header.set_target_count(entries.len() as u32);
        header.set_data_size(bytes.len() as u32);
        bytes[..DmHeader::SIZE].copy_from_slice(header.as_bytes());

        let mut abs_offset_from_first = 0usize;
        for (i, (type_name, params)) in entries.iter().enumerate() {
            let abs_offset = first + abs_offset_from_first;
            let aligned_len = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
            let next = if i == entries.len() - 1 {
                0
            } else {
                (abs_offset_from_first + aligned_len) as u32
            };

            bytes[abs_offset..abs_offset + 8].copy_from_slice(&(i as u64 * 10).to_ne_bytes());
            bytes[abs_offset + 8..abs_offset + 16].copy_from_slice(&(i as u64 + 1).to_ne_bytes());
            bytes[abs_offset + 20..abs_offset + 24].copy_from_slice(&next.to_ne_bytes());
            let type_field = &mut bytes[abs_offset + 24..abs_offset + 24 + DM_MAX_TYPE_NAME];
            type_field[..type_name.len()].copy_from_slice(type_name);

            let param_start = abs_offset + DM_TARGET_SPEC_SIZE;
            bytes[param_start..param_start + params.len()].copy_from_slice(params.as_bytes());

            abs_offset_from_first += aligned_len;
        }

        bytes
    }

    #[test]
    fn response_lazily_yields_borrowed_rows() {
        let bytes = synthetic_table_status_response(&[
            (b"zero", ""),
            (b"linear", "252:5 5"),
            (b"error", ""),
        ]);
        let control = Arc::new(File::open("/dev/null").unwrap());
        let table = Response::<Table>::new(bytes, control).unwrap();
        let rows: Vec<_> = table.rows().collect::<io::Result<_>>().unwrap();

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].span(), Span::new(0, 1));
        assert_eq!(rows[1].span(), Span::new(10, 2));
        assert_eq!(rows[1].name(), "linear");
        assert_eq!(rows[1].params, b"252:5 5");
        assert_eq!(rows[2].name(), "error");
    }

    #[test]
    fn row_debug_redacts_borrowed_parameters() {
        let bytes = synthetic_table_status_response(&[(b"crypt", "secret-key")]);
        let control = Arc::new(File::open("/dev/null").unwrap());
        let table = Response::<Table>::new(bytes, control).unwrap();
        let row = table.rows().next().unwrap().unwrap();
        let debug = format!("{row:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-key"));
    }

    #[test]
    fn malformed_row_boundaries_stop_iteration_safely() {
        // A last-row `next` of zero wins over an excessive target count.
        let mut bytes = synthetic_table_status_response(&[(b"zero", "")]);
        let (header, _) = DmHeader::mut_from_prefix(&mut bytes).unwrap();
        header.set_target_count(3);
        let control = Arc::new(File::open("/dev/null").unwrap());
        let table = Response::<Table>::new(bytes, control).unwrap();
        assert_eq!(
            table.rows().collect::<io::Result<Vec<_>>>().unwrap().len(),
            1
        );

        // An unterminated type field stays within its fixed-width field.
        let mut bytes = synthetic_table_status_response(&[(b"zero", "")]);
        let type_off = DmHeader::SIZE + 24;
        bytes[type_off..type_off + DM_MAX_TYPE_NAME].copy_from_slice(b"abcdefghijklmnop");
        let control = Arc::new(File::open("/dev/null").unwrap());
        let table = Response::<Table>::new(bytes, control).unwrap();
        assert_eq!(
            table.rows().next().unwrap().unwrap().name(),
            "abcdefghijklmnop"
        );

        // A truncated spec is an explicit error rather than a clean end.
        let mut bytes = synthetic_table_status_response(&[(b"zero", "")]);
        bytes.truncate(DmHeader::SIZE + 8);
        let control = Arc::new(File::open("/dev/null").unwrap());
        let table = Response::<Table>::new(bytes, control).unwrap();
        let mut rows = table.rows();
        let error = rows.next().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(rows.next().is_none());
    }
}
