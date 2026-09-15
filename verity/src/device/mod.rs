// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU32;

use crate::{Hashes, Header};

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

/// A read-only, authenticated view of a dm-verity data device.
///
/// Construct with [`crate::traits::std::Open`] or its Tokio counterpart,
/// supplying an opened [`Hashes`] and an externally trusted root digest.
/// Opening checks geometry but performs no authentication. Reads authenticate
/// complete data blocks before returning their contents. A bad root, corrupt
/// block, or unavailable hashing implementation is reported when reading.
///
/// Backing contents must remain unchanged while the view is in use. The
/// reported size is the protected extent; seeking beyond its end is allowed.
/// A cancelled Tokio read resumes on the next read, even with a different
/// output-buffer size. Seeking during a pending read returns
/// [`io::ErrorKind::WouldBlock`]; resume the read first. An I/O or
/// authentication error clears the pending read and leaves the logical
/// position unchanged for that block, allowing a retry or seek.
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "sha1",
        feature = "sha2",
        feature = "sha3",
        feature = "ripemd",
        feature = "whirlpool",
        feature = "streebog",
        feature = "sm3",
        feature = "blake2"
    )))
)]
#[allow(missing_debug_implementations)]
pub struct Verity<D, H> {
    data: D,
    hashes: Hashes<H>,
    root: Box<[u8]>,
    position: u64,
    block_size: NonZeroU32,
    buffer: Vec<u8>,
    cached: Option<u64>,
    #[cfg(feature = "tokio")]
    phase: r#async::Phase,
}

impl<D, H> Verity<D, H> {
    fn new(
        data: D,
        hashes: Hashes<H>,
        root: &[u8],
        block_size: NonZeroU32,
        count: u64,
    ) -> io::Result<Self> {
        let header = hashes.header();
        if root.len() != header.algorithm().digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root digest length does not match the hash algorithm",
            ));
        }
        let length = count
            .checked_mul(u64::from(block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "data geometry overflows"))?;
        if header.data_block_size().get() % block_size.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity data block size is incompatible with the endpoint block size",
            ));
        }
        if length < header.layout.data_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data endpoint is shorter than the declared layout",
            ));
        }
        Ok(Self {
            data,
            hashes,
            root: root.into(),
            position: 0,
            block_size,
            buffer: Vec::new(),
            cached: None,
            #[cfg(feature = "tokio")]
            phase: r#async::Phase::Idle,
        })
    }

    /// Borrows the hash device's validated metadata without performing I/O.
    ///
    /// This does not authenticate the backing contents and remains available
    /// during a pending asynchronous read.
    pub fn header(&self) -> &Header {
        self.hashes.header()
    }

    #[cfg(feature = "tokio")]
    fn ensure_idle(&self) -> io::Result<()> {
        if !matches!(self.phase, r#async::Phase::Idle) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous verity read is in progress",
            ));
        }
        Ok(())
    }

    fn prepare_buffer(&mut self) {
        // Invalidate before overwriting: a failed read must never let the
        // previous block's cache tag authenticate the new buffer contents.
        self.cached = None;
        self.buffer
            .resize(self.header().data_block_size().get() as usize, 0);
    }

    fn copy_authenticated(&mut self, output: &mut [u8]) -> usize {
        let within = (self.position % u64::from(self.header().data_block_size().get())) as usize;
        let count = output.len().min(self.buffer.len() - within);
        output[..count].copy_from_slice(&self.buffer[within..within + count]);
        self.position += count as u64;
        count
    }

    fn seek_position(&mut self, seek: io::SeekFrom) -> io::Result<u64> {
        #[cfg(feature = "tokio")]
        self.ensure_idle()?;
        let next = match seek {
            io::SeekFrom::Start(position) => i128::from(position),
            io::SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            io::SeekFrom::End(delta) => {
                i128::from(self.header().layout.data_size) + i128::from(delta)
            }
        };
        self.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before the start of a verity device",
            )
        })?;
        Ok(self.position)
    }
}
