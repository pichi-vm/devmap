// SPDX-License-Identifier: Apache-2.0

//! Random bytes for default salts and UUIDs, straight from
//! `/dev/urandom` — no crypto dependency for what is a convenience
//! default (the values are cosmetic identity, not a security boundary).

use std::fs::File;
use std::io::{self, Read as _};

/// Read `n` random bytes from `/dev/urandom`.
///
/// # Errors
///
/// The underlying `io::Error` if `/dev/urandom` can't be opened or the
/// read comes up short.
pub(crate) fn bytes(n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}
