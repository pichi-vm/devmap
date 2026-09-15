// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

use devmap_core::traits::std::Geometry;

use super::Verity;
use crate::{Hashes, traits::std::Open};

impl<D: Geometry, H: Geometry> Open<D, Hashes<H>> for Verity<D, H> {
    fn open(mut data: D, mut hashes: Hashes<H>, root: &[u8]) -> io::Result<Self> {
        hashes.validate_storage()?;
        let block_size = data.block_size()?;
        let count = data.count()?;
        Self::new(data, hashes, root, block_size, count)
    }
}

impl<D: Read + Seek, H: Read + Seek> Read for Verity<D, H> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        #[cfg(feature = "tokio")]
        self.ensure_idle()?;
        if output.is_empty() || self.position >= (self.parameters().layout.data_size as u64) {
            return Ok(0);
        }
        let block_size = u64::from(self.parameters().data_block_size().get());
        let block = self.position / block_size;
        if self.cached != Some(block) {
            self.prepare_buffer();
            self.data.seek(SeekFrom::Start(block * block_size))?;
            self.data.read_exact(&mut self.buffer)?;
            self.hashes.authenticate(block, &self.buffer, &self.root)?;
            self.cached = Some(block);
        }
        Ok(self.copy_authenticated(output))
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
        Ok((self.parameters().layout.data_size as u64) / u64::from(self.block_size.get()))
    }
}
