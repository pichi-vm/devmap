// SPDX-License-Identifier: Apache-2.0

//! Linux block-device geometry inspection.

// Defining an ioctl is unsafe; invoking this typed declaration is safe. Keep
// this exception confined to the module that audits the kernel ABI.
#![allow(unsafe_code)]

use std::io;
use std::num::NonZeroU32;
use std::os::fd::AsFd;
use std::os::raw::c_int;

use iocuddle::{Group, Ioctl, Read};

const BLOCK: Group = Group::new(0x12);

// Linux `ENOTTY`, returned when a file does not implement a requested ioctl.
const ENOTTY: c_int = 25;

// SAFETY: Linux defines BLKSSZGET as `_IO(0x12, 104)` but treats its argument
// as an `int *` through which it returns the logical block size. `none` keeps
// that historical opcode encoding while `Ioctl<Read, &c_int>` gives the safe
// invocation the pointer and initialized-output semantics the kernel expects.
const BLKSSZGET: Ioctl<Read, &c_int> = unsafe { BLOCK.none(104) };

/// Returns the logical block size reported by Linux.
///
/// Files that do not implement `BLKSSZGET` are byte-addressable.
pub(super) fn block_size(fd: impl AsFd) -> io::Result<NonZeroU32> {
    let size = match BLKSSZGET.ioctl(fd) {
        Ok((_, size)) => size,
        Err(error) if error.raw_os_error() == Some(ENOTTY) => 1,
        Err(error) => return Err(error),
    };

    u32::try_from(size)
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}
