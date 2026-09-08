// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::SyncData;

use super::Merge;

impl<O, C> Merge<O, C>
where
    O: Read + Write + Seek + SyncData,
    C: Read + Write + Seek + SyncData,
{
    /// Runs the merge to completion, returning the origin and empty store.
    pub fn run(mut self) -> io::Result<(O, C)> {
        self.layer()?.sync_data()?;
        self.prepare()?;
        self.preflight()?;
        let chunk_bytes = self.layer()?.chunk_bytes()?;

        for index in 0..self.plan.len() {
            let (origin, cow) = self.plan[index];
            let cow_offset = cow.checked_mul(chunk_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "COW offset overflows")
            })?;
            self.layer()?.cow_mut()?.seek(SeekFrom::Start(cow_offset))?;
            let mut chunk = std::mem::take(&mut self.chunk);
            let read = self.layer()?.cow_mut()?.read_exact(&mut chunk);
            self.chunk = chunk;
            read?;

            let origin_offset = origin.checked_mul(chunk_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "origin offset overflows")
            })?;
            let valid =
                usize::try_from((self.layer()?.origin_bytes - origin_offset).min(chunk_bytes))
                    .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
            self.layer()?
                .origin_mut()?
                .seek(SeekFrom::Start(origin_offset))?;
            let chunk = std::mem::take(&mut self.chunk);
            let written = self.layer()?.origin_mut()?.write_all(&chunk[..valid]);
            self.chunk = chunk;
            written?;
        }

        self.layer()?.origin_mut()?.flush()?;
        self.layer()?.origin_mut()?.sync_data()?;
        let areas = self.areas()?;
        let zeros = vec![0; self.layer()?.chunk_usize()?];
        for area in (0..areas).rev() {
            let metadata = self.layer()?.loaded()?.metadata_chunk(area)?;
            let position = metadata.checked_mul(chunk_bytes).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "metadata offset overflows")
            })?;
            self.layer()?.cow_mut()?.seek(SeekFrom::Start(position))?;
            self.layer()?.cow_mut()?.write_all(&zeros)?;
        }
        self.layer()?.cow_mut()?.flush()?;
        self.layer()?.cow_mut()?.sync_data()?;
        self.layer()?.loaded()?.clear();
        self.take_parts()
    }
}
