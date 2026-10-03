// SPDX-License-Identifier: Apache-2.0

use crate::{BlockSize, Constraint, Geometry};
#[cfg(target_os = "linux")]
use iocuddle::{Group, Ioctl, Read};
use std::{fs::File, io, num::NonZero};
#[cfg(target_os = "linux")]
use std::{os::fd::AsFd, os::unix::fs::FileTypeExt as _};

#[cfg(target_os = "linux")]
const BLOCK: Group = Group::new(0x12);

// SAFETY: BLKSSZGET is `_IO(0x12, 104)` in <linux/fs.h>, but writes an
// `int` through its argument despite carrying no direction bits. The
// classic request number and `u32` output match that stable Linux ABI.
#[cfg(target_os = "linux")]
#[expect(unsafe_code, reason = "declares the documented Linux ioctl ABI")]
const BLKSSZGET: Ioctl<Read, &u32> = unsafe { Ioctl::classic(0x1268) };

// SAFETY: BLKGETSIZE64 is `_IOR(0x12, 114, size_t)` in <linux/fs.h>, so
// the request encodes the native `size_t` width. The kernel operation
// nevertheless writes a `u64`; the returned reference guarantees eight
// writable bytes on both 32- and 64-bit Linux.
#[cfg(target_os = "linux")]
#[expect(unsafe_code, reason = "declares the documented Linux ioctl ABI")]
const BLKGETSIZE64: Ioctl<Read, &u64> = unsafe { BLOCK.read::<usize>(114).lie::<Read, &u64>() };

/// Detects a value from an open file.
///
/// Detection is synchronous, including when the file will later be used
/// through asynchronous I/O. Regular files use the constraint's default
/// block size. On Linux, block devices use their reported logical block size
/// and byte extent.
pub trait Detect: Sized {
    /// Detects this value from the file's complete extent.
    ///
    /// # Errors
    ///
    /// Returns an underlying metadata error, or [`io::ErrorKind::InvalidInput`]
    /// when the file type, block size, or extent cannot represent `Self`.
    fn detect(file: &File) -> io::Result<Self>;
}

impl<C: Constraint> Detect for BlockSize<C> {
    fn detect(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if metadata.is_file() {
            return Ok(Self::default());
        }

        #[cfg(target_os = "linux")]
        if metadata.file_type().is_block_device() {
            let (_, bytes) = BLKSSZGET.ioctl(file.as_fd())?;
            return NonZero::new(bytes)
                .and_then(Self::from_bytes)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "logical block size is outside the permitted range",
                    )
                });
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage must be a regular file or supported block device",
        ))
    }
}

impl<C: Constraint> Detect for Geometry<C> {
    fn detect(file: &File) -> io::Result<Self> {
        let size = BlockSize::detect(file)?;
        let metadata = file.metadata()?;

        let extent = if metadata.is_file() {
            metadata.len()
        } else {
            #[cfg(target_os = "linux")]
            if metadata.file_type().is_block_device() {
                let (_, bytes) = BLKGETSIZE64.ioctl(file.as_fd())?;
                bytes
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "storage must be a regular file or supported block device",
                ));
            }

            #[cfg(not(target_os = "linux"))]
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage must be a regular file",
            ));
        };

        let block = u64::from(size.bytes().get());

        if extent == 0 || extent % block != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage extent must be a nonzero whole number of blocks",
            ));
        }

        Ok(Self {
            size,
            count: NonZero::new(extent / block).expect("storage extent is nonzero"),
        })
    }
}
