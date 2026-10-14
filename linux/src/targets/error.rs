// SPDX-License-Identifier: Apache-2.0

//! The Linux device-mapper `error` target.

use std::io;

use super::{Target, Version};

/// Fails I/O to the mapped sector range.
///
/// Encodes the parameterless form. The optional backing-device configuration
/// is not supported by this type. The kernel reports no table parameters or
/// runtime info; both response types are `()`.
///
/// Add this target with [`Table::add`](crate::Table::add). Encoding supports
/// target major version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error;

impl Target for Error {
    const NAME: &'static str = "error";

    type Table = ();
    type Info = ();

    fn encode(&self, version: Version, output: &mut (impl io::Write + ?Sized)) -> io::Result<()> {
        if version.major != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported error target version",
            ));
        }
        output.write_all(b"")
    }
}
