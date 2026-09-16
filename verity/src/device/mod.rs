// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::NonZeroU32;

use crate::hashes::authentication::Mismatch;
use crate::{CorruptionPolicy, Hashes, IoErrorPolicy, Options};
use digest::DynDigest;

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

/// A read-only verity view with explicit verification policies.
///
/// Construct through [`crate::Options`] using the synchronous or Tokio
/// `Open` trait. Opening checks geometry but authenticates no data.
/// Default options authenticate complete blocks before returning bytes.
/// [`CorruptionPolicy::Ignore`] permits unauthenticated data after a detected
/// mismatch; `check_at_most_once` skips verification of previously verified blocks.
/// Transport errors are never suppressed.
///
/// Treat both backing volumes as immutable. The view exposes the protected
/// extent and allows seeking beyond it. Copy it to an I/O sink under default
/// options to check the entire extent. An unavailable hash implementation is
/// reported on read.
///
/// A cancelled Tokio read resumes on the next read, including with a different
/// output-buffer size. Seeking during a pending read returns `WouldBlock`.
/// I/O or authentication errors clear pending state and leave the position
/// unchanged for that block, allowing a retry or seek.
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
    options: Options<'static>,
    digests: Option<Digests>,
    compare: bool,
    verified: Vec<u8>,
    #[cfg(feature = "tokio")]
    phase: r#async::Phase,
}

impl<D, H> Verity<D, H> {
    fn new(
        data: D,
        hashes: Hashes<H>,
        root: &[u8],
        options: Options<'_>,
        block_size: NonZeroU32,
        count: u64,
    ) -> io::Result<Self> {
        let layout = &hashes.layout;
        if options.hash_start_block != 1
            || options.try_verify_in_tasklet
            || options.fec.is_some()
            || options.root_hash_sig_key_desc.is_some()
            || options.io_error_policy != IoErrorPolicy::Error
            || !matches!(
                options.corruption_policy,
                CorruptionPolicy::Error | CorruptionPolicy::Ignore
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "verity options are not supported by userspace verification",
            ));
        }
        options.validate(layout)?;
        if root.len() != layout.algorithm().digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root digest length does not match the hash algorithm",
            ));
        }
        let length = count
            .checked_mul(u64::from(block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "data geometry overflows"))?;
        if layout.data_block_size().get() % block_size.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity data block size is incompatible with the endpoint block size",
            ));
        }
        if length < layout.data_size as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data endpoint is shorter than the declared layout",
            ));
        }
        let mut verified = Vec::new();
        if options.check_at_most_once {
            let bytes = usize::try_from(layout.data_blocks().get().div_ceil(8))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            verified
                .try_reserve_exact(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            verified.resize(bytes, 0);
        }
        Ok(Self {
            data,
            hashes,
            root: root.into(),
            position: 0,
            block_size,
            buffer: Vec::new(),
            cached: None,
            options: options.without_signature(),
            digests: None,
            compare: false,
            verified,
            #[cfg(feature = "tokio")]
            phase: r#async::Phase::Idle,
        })
    }

    /// Borrows the hash device for metadata access without I/O.
    pub const fn hashes(&self) -> &Hashes<H> {
        &self.hashes
    }

    /// Returns the accepted read policies.
    pub const fn options(&self) -> Options<'_> {
        self.options
    }

    fn data_block_size(&self) -> u64 {
        u64::from(u32::from(self.hashes.shape().data_block_size))
    }
    fn data_size(&self) -> u64 {
        self.hashes.layout.data_size as u64
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

    fn prepare_buffer(&mut self) -> io::Result<()> {
        // Invalidate before overwriting, including after failed verification.
        self.cached = None;
        self.compare = false;
        self.buffer.resize(self.data_block_size() as usize, 0);
        if self.digests.is_none() {
            let scheme = self.hashes.scheme();
            let hasher = scheme.algorithm.hasher().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "hash algorithm support is not enabled",
                )
            })?;
            let size = scheme.algorithm.digest_size();
            let mut digests = Digests {
                hasher,
                expected: vec![0; size].into_boxed_slice(),
                actual: vec![0; size].into_boxed_slice(),
                zero: None,
            };
            if self.options.ignore_zero_blocks {
                self.buffer.fill(0);
                let mut zero = vec![0; size].into_boxed_slice();
                scheme.hash_type.digest(
                    digests.hasher.as_mut(),
                    scheme.salt.as_slice(),
                    &self.buffer,
                    &mut zero,
                )?;
                digests.zero = Some(zero);
            }
            self.digests = Some(digests);
        }
        Ok(())
    }

    fn was_verified(&self, block: u64) -> bool {
        !self.verified.is_empty() && self.verified[block as usize / 8] & (1 << (block % 8)) != 0
    }

    fn mark_verified(&mut self, block: u64) {
        if !self.verified.is_empty() {
            self.verified[block as usize / 8] |= 1 << (block % 8);
        }
    }

    fn ignore_mismatch(policy: CorruptionPolicy, error: &io::Error) -> bool {
        policy == CorruptionPolicy::Ignore
            && match error.get_ref() {
                Some(cause) => cause.is::<Mismatch>(),
                None => false,
            }
    }

    fn zero_block(&mut self, block: u64) -> bool {
        if self.compare
            && self
                .digests
                .as_ref()
                .is_some_and(|d| d.zero.as_deref() == Some(d.expected.as_ref()))
        {
            self.buffer.fill(0);
            // Synthesized zeroes do not validate the backing data. Keep looking
            // up their digest after cache eviction, even with check_at_most_once.
            self.cached = Some(block);
            return true;
        }
        false
    }

    fn finish_block(&mut self, block: u64) -> io::Result<()> {
        if self.compare {
            let scheme = self.hashes.scheme();
            let d = self
                .digests
                .as_mut()
                .ok_or_else(|| io::Error::other("missing data verifier"))?;
            scheme.hash_type.digest(
                d.hasher.as_mut(),
                scheme.salt.as_slice(),
                &self.buffer,
                &mut d.actual,
            )?;
            if d.actual == d.expected {
                self.mark_verified(block);
            } else if self.options.corruption_policy != CorruptionPolicy::Ignore {
                return Err(io::Error::new(io::ErrorKind::InvalidData, Mismatch));
            }
        }
        self.cached = Some(block);
        Ok(())
    }

    fn copy_ready(&mut self, output: &mut [u8]) -> usize {
        let within = (self.position % self.data_block_size()) as usize;
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
            io::SeekFrom::End(delta) => i128::from(self.data_size()) + i128::from(delta),
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

struct Digests {
    hasher: Box<dyn DynDigest + Send + Sync>,
    expected: Box<[u8]>,
    actual: Box<[u8]>,
    zero: Option<Box<[u8]>>,
}
