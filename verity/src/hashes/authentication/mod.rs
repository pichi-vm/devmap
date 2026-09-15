// SPDX-License-Identifier: Apache-2.0

use std::io;

use digest::DynDigest;

use super::Hashes;
use crate::Parameters;

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

pub(super) struct State {
    hasher: Box<dyn DynDigest + Send + Sync>,
    digest: Box<[u8]>,
    block: Box<[u8]>,
    #[cfg(feature = "tokio")]
    phase: r#async::Phase,
}

impl State {
    fn new(parameters: &Parameters) -> io::Result<Self> {
        let hasher = parameters.algorithm().hasher().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "hash algorithm support is not enabled",
            )
        })?;
        Ok(Self {
            hasher,
            digest: vec![0; parameters.algorithm().digest_size()].into_boxed_slice(),
            block: vec![0; parameters.hash_block_size().get() as usize].into_boxed_slice(),
            #[cfg(feature = "tokio")]
            phase: r#async::Phase::Idle,
        })
    }

    fn begin(&mut self, parameters: &Parameters, index: u64, data: &[u8]) -> io::Result<()> {
        if index >= parameters.data_blocks().get()
            || data.len() != parameters.data_block_size().get() as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid verity data block",
            ));
        }
        parameters.hash_type().digest(
            self.hasher.as_mut(),
            parameters.salt(),
            data,
            &mut self.digest,
        )
    }

    fn advance(&mut self, parameters: &Parameters, child: u64) -> io::Result<()> {
        let slot = (child % parameters.layout.hashes_per_block as u64) as usize;
        let start = slot * parameters.layout.slot_size;
        if self.block.get(start..start + self.digest.len()) != Some(self.digest.as_ref()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity data authentication failed",
            ));
        }
        parameters.hash_type().digest(
            self.hasher.as_mut(),
            parameters.salt(),
            &self.block,
            &mut self.digest,
        )
    }

    fn check_root(&self, root: &[u8]) -> io::Result<()> {
        if self.digest.as_ref() != root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity root digest does not match",
            ));
        }
        Ok(())
    }

    fn offset(parameters: &Parameters, level: usize, child: u64) -> u64 {
        // Header validation bounds the complete tree in bytes; begin bounds the child.
        u64::from(parameters.hash_block_size().get())
            + parameters.layout.level_offsets[level] as u64
            + (child / parameters.layout.hashes_per_block as u64)
                * u64::from(parameters.hash_block_size().get())
    }
}

impl<H> Hashes<H> {
    fn validate_geometry(&self, block_size: std::num::NonZeroU32, count: u64) -> io::Result<()> {
        let bytes = count
            .checked_mul(u64::from(block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "hash geometry overflows"))?;
        if self.parameters.hash_block_size().get() % block_size.get() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verity hash block size is incompatible with the endpoint block size",
            ));
        }
        if u128::from(bytes) < self.parameters.layout.hash_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hash endpoint is shorter than the declared layout",
            ));
        }
        Ok(())
    }
}
