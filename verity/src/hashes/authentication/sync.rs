// SPDX-License-Identifier: Apache-2.0

use super::{Hashes, State};
use devmap_core::traits::std::Geometry;
use std::io::{self, Read, Seek, SeekFrom};

impl<H: Geometry> Hashes<H> {
    pub(crate) fn validate_storage(&mut self) -> io::Result<()> {
        let block_size = self.inner.block_size()?;
        let count = self.inner.count()?;
        self.validate_geometry(block_size, count)
    }
}

impl<H: Read + Seek> Hashes<H> {
    pub(crate) fn lookup(&mut self, index: u64, root: &[u8]) -> io::Result<&[u8]> {
        if self.authentication.is_none() {
            self.authentication = Some(State::new(&self.layout)?);
        }
        let state = self
            .authentication
            .as_mut()
            .ok_or_else(|| io::Error::other("missing verifier"))?;
        #[cfg(feature = "tokio")]
        if !matches!(state.phase, super::r#async::Phase::Idle) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "hash lookup is in progress",
            ));
        }
        state.begin(&self.layout, index, root)?;
        for level in (0..self.layout.level_offsets.len()).rev() {
            self.inner
                .seek(SeekFrom::Start(State::offset(&self.layout, level, index)))?;
            self.inner.read_exact(&mut state.block)?;
            state.advance(&self.layout, level, index)?;
        }
        Ok(&state.expected)
    }
}
