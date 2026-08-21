// SPDX-License-Identifier: Apache-2.0

//! How big a thing is, and how many sectors that comes to.
//!
//! Every persona has to answer the same question before it can build a
//! table: the kernel measures a mapping in 512-byte sectors, and what the
//! user hands us is a byte count. Both halves live here so no persona has
//! to work either out again.
//!
//! Sizing goes through a seek to the end rather than `metadata().len()`,
//! which is the inode's `st_size`. A block device's size is not in its
//! inode — it belongs to the device — so `st_size` reads back as zero for
//! one, and every persona here accepts a block device.

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};

/// Bytes per sector — the unit of a dm table's start, length, and offsets.
pub(crate) const SECTOR: u64 = 512;

/// The size in bytes of an open file or block device.
///
/// The read cursor is left where it was found, so a caller can size a
/// handle it is about to read from.
///
/// # Errors
///
/// The underlying `io::Error` if the handle can't be seeked. The caller
/// knows which device this is, so it adds that context.
pub(crate) fn of(file: &File) -> io::Result<u64> {
    // `Seek` is implemented for `&File`, so this needs no `&mut File`.
    let mut handle = file;
    let resume_at = handle.stream_position()?;
    let end = handle.seek(SeekFrom::End(0))?;
    handle.seek(SeekFrom::Start(resume_at))?;
    Ok(end)
}
