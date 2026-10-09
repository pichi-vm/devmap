// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fs::File;
use std::io;
use std::marker::PhantomData;

use devmap_core::Span;

use crate::target::{Parse, Target};

use super::Mode;

/// A target's sector range and kernel response, returned by
/// [`Device::table`](crate::device::Device::table) or
/// [`Device::info`](crate::device::Device::info).
///
/// Call [`parse`](Row::parse) with the expected [`Target`] type. A table row
/// yields `T::Table`; an info row yields `T::Info`. A different target name
/// produces `InvalidInput`; an undecodable response produces `InvalidData`.
/// The kernel target version is supplied to the target's parser automatically.
/// Raw response parameters are not exposed; `Debug` redacts them.
pub struct Row<'a, M> {
    pub(super) span: Span<u64>,
    pub(super) type_name: &'a str,
    pub(super) params: &'a [u8],
    pub(super) control: &'a File,
    pub(super) _mode: PhantomData<M>,
}

impl<M> fmt::Debug for Row<'_, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Row")
            .field("span", &self.span)
            .field("type_name", &self.type_name)
            .field("params", &"<redacted>")
            .finish()
    }
}

impl<M> Row<'_, M> {
    /// Sector span covered by this row.
    pub fn span(&self) -> Span<u64> {
        self.span
    }

    /// Kernel target name for this row.
    pub fn name(&self) -> &str {
        self.type_name
    }
}

impl<M: Mode> Row<'_, M> {
    /// Parse this row as the response type associated with target `T`.
    ///
    /// Returns `InvalidInput` for a different target name or `InvalidData`
    /// when the target cannot parse the reported response or version.
    pub fn parse<T: Target>(&self) -> io::Result<M::Parsed<T>> {
        if self.type_name != T::NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected target {}, found {}", T::NAME, self.type_name),
            ));
        }
        let params = std::str::from_utf8(self.params)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let version = crate::control::target_version(self.control, T::NAME).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("query version for target {:?}: {error}", T::NAME),
            )
        })?;
        <M::Parsed<T> as Parse>::parse(params, version)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}
