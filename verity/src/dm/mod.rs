// SPDX-License-Identifier: Apache-2.0

//! Linux verity target descriptions, available without hashing dependencies.
//!
//! Construct a target through [`crate::Parameters::target`] and pass it to a backend
//! such as `devmap-linux` for activation.

use devmap_core::parse::Error;
use std::{fmt, str::FromStr};

mod codec;
mod options;
mod target;
pub use options::{CorruptionPolicy, Fec, IoErrorPolicy};
pub use target::VerityTarget;

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
