// SPDX-License-Identifier: Apache-2.0

//! The `integrity` (dm-integrity) target: adds per-block integrity tags to
//! a device so silent data corruption can be detected.

use std::fmt::{self, Write as _};

use crate::DevId;
use crate::table::{RawInfo, Target};

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
    const TYPE_NAME: &'static str = "integrity";
    type Info = RawInfo;
}
impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self.mode {
            Mode::Direct => 'D',
            Mode::Journaled => 'J',
            Mode::Bitmap => 'B',
            Mode::Recovery => 'R',
            Mode::Inline => 'I',
        };
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
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn integrity_renders_dash_for_unset_tag_size() {
        // internal_hash lets the kernel derive the tag size, so tag_size
        // may stay unset (renders `-`).
        let t = Integrity::builder(DevId::new(252, 1), 0, Mode::Journaled)
            .internal_hash("sha256")
            .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 integrity 252:1 0 - J 1 internal_hash:sha256"
        );
    }

    #[test]
    fn integrity_renders_optional_args() {
        let t = Integrity::builder(DevId::new(252, 1), 0, Mode::Direct)
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
        let bitmap = Integrity::builder(DevId::new(252, 1), 0, Mode::Bitmap)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &bitmap).contains(" B "));
        let recovery = Integrity::builder(DevId::new(252, 1), 0, Mode::Recovery)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &recovery).contains(" R "));
        let inline = Integrity::builder(DevId::new(252, 1), 0, Mode::Inline)
            .internal_hash("sha256")
            .build();
        assert!(line(0, 8192, &inline).contains(" I "));
    }
}
