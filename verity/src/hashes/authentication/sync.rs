// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

use devmap_core::traits::std::Geometry;

use super::{Hashes, State};

impl<H: Geometry> Hashes<H> {
    pub(crate) fn validate_storage(&mut self) -> io::Result<()> {
        let block_size = self.inner.block_size()?;
        let count = self.inner.count()?;
        self.validate_geometry(block_size, count)
    }
}

impl<H: Read + Seek> Hashes<H> {
    pub(crate) fn authenticate(&mut self, index: u64, data: &[u8], root: &[u8]) -> io::Result<()> {
        if self.authentication.is_none() {
            self.authentication = Some(State::new(&self.parameters)?);
        }
        let state = self
            .authentication
            .as_mut()
            .ok_or_else(|| io::Error::other("missing verifier"))?;
        #[cfg(feature = "tokio")]
        if !matches!(state.phase, super::r#async::Phase::Idle) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "authentication is in progress",
            ));
        }
        state.begin(&self.parameters, index, data)?;
        let mut child = index;
        for level in 0..self.parameters.layout.level_offsets.len() {
            self.inner.seek(SeekFrom::Start(State::offset(
                &self.parameters,
                level,
                child,
            )))?;
            self.inner.read_exact(&mut state.block)?;
            state.advance(&self.parameters, child)?;
            child /= self.parameters.layout.hashes_per_block as u64;
        }
        state.check_root(root)
    }
}
