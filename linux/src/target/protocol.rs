// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::fmt;

use super::Version;

/// Parse a target's kernel response for a target version.
///
/// An unversioned `FromStr` implementation may be used internally, but is not
/// required. Types with different table and runtime grammars should be modeled
/// as distinct types.
pub trait Parse: Sized {
    /// Why the response could not be parsed for this version.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Decode the parameters reported by the kernel.
    fn parse(text: &str, version: Version) -> Result<Self, Self::Error>;
}

impl Parse for String {
    type Error = Infallible;

    fn parse(text: &str, _: Version) -> Result<Self, Self::Error> {
        Ok(text.to_owned())
    }
}

/// The installed kernel target version cannot encode this configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError {
    /// Version reported by the kernel.
    pub version: Version,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported target version {}.{}.{}",
            self.version.major, self.version.minor, self.version.patch
        )
    }
}

impl std::error::Error for EncodeError {}

/// A loadable Linux device-mapper target.
///
/// A device-mapper table contains rows, each covering a sector range.
/// [`Builder::add`](crate::device::Builder::add) supplies that range, uses
/// [`NAME`](Self::NAME) for the kernel target name, and calls [`encode`](Self::encode)
/// with the installed target version. Creating the device and
/// loading its table are separate operations.
///
/// The kernel can later report each row in two modes:
///
/// - `STATUSTYPE_TABLE` reports the row's construction parameters. Parse
///   those parameters as [`Table`](Self::Table).
/// - `STATUSTYPE_INFO` reports the target's current runtime state. Parse
///   that state as [`Info`](Self::Info).
///
/// Table read-back is not necessarily a loadable target. The kernel may
/// normalize, omit, or redact inputs. When read-back loses information,
/// `Table` should be a distinct type that can be converted into a target
/// only after the caller supplies the missing information. When read-back
/// retains everything needed, implementations commonly use `Self` for
/// `Table`. `Info` describes runtime state, not construction parameters.
pub trait Target: Sized {
    /// The kernel target name written into a table row.
    ///
    /// Must be nonempty, shorter than 16 bytes, and contain neither NUL nor
    /// whitespace.
    const NAME: &'static str;

    /// Encode construction parameters for the installed kernel target version.
    ///
    /// Return [`EncodeError`] if this configuration cannot be expressed for
    /// that version. The version is a property of the kernel target, not the
    /// device-mapper ioctl protocol. A passing version check does not prove
    /// that the kernel accepts the configuration: cipher availability,
    /// backing devices, and kernel build options are checked during table load.
    fn encode(&self, version: Version) -> Result<String, EncodeError>;

    /// Parameters returned for this target in `STATUSTYPE_TABLE` mode.
    ///
    /// This type represents what the kernel reports, not necessarily the
    /// value originally passed to [`Builder::add`](crate::device::Builder::add).
    /// A lossy report should not be modeled as a loadable target merely
    /// because its text parses successfully.
    type Table: Parse;

    /// Runtime state returned for this target in `STATUSTYPE_INFO` mode.
    ///
    /// Use [`Empty`](crate::target::Empty) when the kernel reports no runtime fields.
    type Info: Parse;
}
