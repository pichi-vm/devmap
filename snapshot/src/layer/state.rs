// SPDX-License-Identifier: Apache-2.0

//! The exception store's geometry, allocator, and metadata buffer.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::chunk_size::EXCEPTION_LEN;

const HEADER_CHUNKS: u64 = 1;

fn malformed(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

pub(crate) fn buffer(size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| io::Error::other(error.to_string()))?;
    bytes.resize(size, 0);
    Ok(bytes)
}

pub(crate) struct State {
    exceptions: BTreeMap<u64, u64>,
    occupied: BTreeSet<u64>,
    next_free: u64,
    count: u64,
    area: u64,
    per_area: u64,
    buffer: Vec<u8>,
    dirty: bool,
}

impl State {
    pub(crate) fn new(chunk_bytes: usize) -> io::Result<Self> {
        Ok(Self {
            exceptions: BTreeMap::new(),
            occupied: BTreeSet::new(),
            next_free: HEADER_CHUNKS,
            count: 0,
            area: 0,
            per_area: u64::try_from(chunk_bytes / EXCEPTION_LEN)
                .map_err(|_| malformed("snapshot chunk size is not addressable"))?,
            buffer: buffer(chunk_bytes)?,
            dirty: false,
        })
    }

    pub(crate) const fn exception_count(&self) -> u64 {
        self.count
    }

    pub(crate) fn lookup(&self, origin: u64) -> Option<u64> {
        self.exceptions.get(&origin).copied()
    }

    pub(crate) fn exceptions(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.exceptions
            .iter()
            .map(|(&origin, &chunk)| (origin, chunk))
    }

    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub(crate) const fn is_dirty(&self) -> bool {
        self.dirty
    }

    fn stride(&self) -> io::Result<u64> {
        self.per_area
            .checked_add(1)
            .ok_or_else(|| malformed("snapshot metadata geometry overflows"))
    }

    pub(crate) fn metadata_chunk(&self, area: u64) -> io::Result<u64> {
        area.checked_mul(self.stride()?)
            .and_then(|offset| offset.checked_add(HEADER_CHUNKS))
            .ok_or_else(|| malformed("snapshot metadata area is not addressable"))
    }

    pub(crate) fn current_metadata_chunk(&self) -> io::Result<u64> {
        self.metadata_chunk(self.area)
    }

    fn is_metadata(&self, chunk: u64) -> io::Result<bool> {
        Ok(chunk >= HEADER_CHUNKS && (chunk - HEADER_CHUNKS) % self.stride()? == 0)
    }

    fn skip_metadata(&self, candidate: u64) -> io::Result<u64> {
        if self.is_metadata(candidate)? {
            candidate
                .checked_add(1)
                .ok_or_else(|| malformed("the copy-on-write store is not addressable"))
        } else {
            Ok(candidate)
        }
    }

    pub(crate) fn plan(&self, origin: u64, cow_chunks: u64) -> io::Result<(u64, bool)> {
        if let Some(chunk) = self.lookup(origin) {
            return Ok((chunk, false));
        }
        let chunk = self.skip_metadata(self.next_free)?;
        let mut highest = chunk.max(self.current_metadata_chunk()?);
        if (self.count + 1) % self.per_area == 0 {
            highest = highest.max(self.metadata_chunk(self.area + 1)?);
        }
        if highest.checked_add(1).is_none_or(|end| end > cow_chunks) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "the copy-on-write store is full",
            ));
        }
        Ok((chunk, true))
    }

    pub(crate) fn commit(
        &mut self,
        origin: u64,
        chunk: u64,
        fresh: bool,
    ) -> io::Result<Option<u64>> {
        if !fresh {
            return Ok(None);
        }
        let slot = usize::try_from(self.count % self.per_area)
            .map_err(|_| malformed("snapshot metadata slot is not addressable"))?;
        let offset = slot * EXCEPTION_LEN;
        self.buffer[offset..offset + 8].copy_from_slice(&origin.to_le_bytes());
        self.buffer[offset + 8..offset + EXCEPTION_LEN].copy_from_slice(&chunk.to_le_bytes());
        self.exceptions.insert(origin, chunk);
        self.occupied.insert(chunk);
        self.next_free = chunk
            .checked_add(1)
            .ok_or_else(|| malformed("the copy-on-write store is not addressable"))?;
        self.count += 1;
        self.dirty = true;
        if self.count % self.per_area == 0 {
            return self.current_metadata_chunk().map(Some);
        }
        Ok(None)
    }

    pub(crate) fn terminator_chunk(&self) -> io::Result<u64> {
        self.metadata_chunk(self.area + 1)
    }

    pub(crate) fn advance_area(&mut self) {
        self.area += 1;
        self.buffer.fill(0);
        self.dirty = false;
    }

    pub(crate) fn published(&mut self) {
        self.dirty = false;
    }

    pub(crate) fn absorb_area(&mut self, area: u64, cow_chunks: u64) -> io::Result<bool> {
        self.area = area;
        for slot in 0..self.per_area {
            let offset = usize::try_from(slot)
                .map_err(|_| malformed("snapshot metadata slot is not addressable"))?
                * EXCEPTION_LEN;
            let origin = u64::from_le_bytes(
                self.buffer[offset..offset + 8]
                    .try_into()
                    .map_err(|_| malformed("truncated snapshot exception"))?,
            );
            let chunk = u64::from_le_bytes(
                self.buffer[offset + 8..offset + EXCEPTION_LEN]
                    .try_into()
                    .map_err(|_| malformed("truncated snapshot exception"))?,
            );
            if chunk == 0 {
                return Ok(true);
            }
            if chunk >= cow_chunks {
                return Err(malformed("snapshot exception points outside the store"));
            }
            if self.is_metadata(chunk)? {
                return Err(malformed("snapshot exception points at store metadata"));
            }
            if !self.occupied.insert(chunk) {
                return Err(malformed("two snapshot exceptions share one store chunk"));
            }
            if self.exceptions.insert(origin, chunk).is_some() {
                return Err(malformed("duplicate origin chunk in the exception store"));
            }
            self.count += 1;
            self.next_free = self.next_free.max(
                chunk
                    .checked_add(1)
                    .ok_or_else(|| malformed("snapshot exception is not addressable"))?,
            );
        }
        Ok(false)
    }

    pub(crate) fn clear(&mut self) {
        self.exceptions.clear();
        self.occupied.clear();
        self.next_free = HEADER_CHUNKS;
        self.count = 0;
        self.area = 0;
        self.buffer.fill(0);
        self.dirty = false;
    }
}
