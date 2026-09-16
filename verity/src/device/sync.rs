// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

use devmap_core::traits::std::Geometry;

use super::Verity;
use crate::{Hashes, Options, traits::std::Open};

impl<D: Geometry, H: Geometry> Open<D, H> for Options<'_> {
    fn open(self, mut data: D, mut hashes: Hashes<H>, root: &[u8]) -> io::Result<Verity<D, H>> {
        hashes.validate_storage()?;
        let block_size = data.block_size()?;
        let count = data.count()?;
        Verity::new(data, hashes, root, self, block_size, count)
    }
}

impl<D: Read + Seek, H: Read + Seek> Read for Verity<D, H> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        #[cfg(feature = "tokio")]
        self.ensure_idle()?;
        if output.is_empty() || self.position >= self.data_size() {
            return Ok(0);
        }
        let block_size = self.data_block_size();
        let block = self.position / block_size;
        if self.cached != Some(block) {
            self.prepare_buffer()?;
            if !self.was_verified(block) {
                match self.hashes.lookup(block, &self.root) {
                    Ok(expected) => {
                        let d = self
                            .digests
                            .as_mut()
                            .ok_or_else(|| io::Error::other("missing data verifier"))?;
                        d.expected.copy_from_slice(expected);
                        self.compare = true;
                    }
                    Err(error) if Self::ignore_mismatch(self.options.corruption_policy, &error) => {
                    }
                    Err(error) => return Err(error),
                }
                if self.zero_block(block) {
                    return Ok(self.copy_ready(output));
                }
            }
            self.data.seek(SeekFrom::Start(block * block_size))?;
            self.data.read_exact(&mut self.buffer)?;
            self.finish_block(block)?;
        }
        Ok(self.copy_ready(output))
    }
}

impl<D, H> Seek for Verity<D, H> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        self.seek_position(seek)
    }
}

impl<D, H> Geometry for Verity<D, H> {
    fn block_size(&self) -> io::Result<std::num::NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> io::Result<u64> {
        Ok(self.data_size() / u64::from(self.block_size.get()))
    }
}
