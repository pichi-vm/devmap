// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use devmap_core::traits::std::{Geometry, SyncData};

use crate::chunk_size::{ChunkSize, Header};
use crate::traits::std::{Compact, Create, Merge, Open};

use super::Layer;
use super::state::{State, buffer};

fn read_at<R: Read + Seek>(reader: &mut R, position: u64, bytes: &mut [u8]) -> io::Result<()> {
    reader.seek(SeekFrom::Start(position))?;
    reader.read_exact(bytes)
}

impl<O, C> Geometry for Layer<O, C> {
    fn block_size(&self) -> io::Result<std::num::NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> io::Result<u64> {
        self.ready()?;
        Ok(self.origin_bytes / u64::from(self.block_size.get()))
    }
}

impl<O, C> Create<O, C> for Layer<O, C>
where
    O: Geometry,
    C: Write + Seek + Geometry + SyncData,
{
    fn create(mut origin: O, mut cow: C, chunk_size: std::num::NonZeroU32) -> io::Result<Self> {
        let origin_block_size = origin.block_size()?;
        let cow_block_size = cow.block_size()?;
        let origin_bytes = origin
            .count()?
            .checked_mul(u64::from(origin_block_size.get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "origin geometry overflows")
            })?;
        let cow_bytes = cow
            .count()?
            .checked_mul(u64::from(cow_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "COW geometry overflows"))?;
        let chunk_size = ChunkSize::new(chunk_size)?;
        let block_size = Self::combined_block_size(origin_block_size, cow_block_size)?;
        Self::validate_geometry(
            origin_bytes,
            cow_bytes,
            chunk_size,
            origin_block_size,
            cow_block_size,
            block_size,
        )?;
        let state = State::new(chunk_size.len())?;
        let mut layer = Self::from_parts(
            origin,
            cow,
            origin_bytes,
            cow_bytes,
            chunk_size,
            block_size,
            state,
        );
        layer.initialize()?;
        Ok(layer)
    }
}

impl<O, C> Open<O, C> for Layer<O, C>
where
    O: Geometry,
    C: Read + Seek + Geometry,
{
    fn open(mut origin: O, mut cow: C) -> io::Result<Self> {
        let origin_block_size = origin.block_size()?;
        let cow_block_size = cow.block_size()?;
        let origin_bytes = origin
            .count()?
            .checked_mul(u64::from(origin_block_size.get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "origin geometry overflows")
            })?;
        let cow_bytes = cow
            .count()?
            .checked_mul(u64::from(cow_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "COW geometry overflows"))?;
        let block_size = Self::combined_block_size(origin_block_size, cow_block_size)?;
        if cow_bytes < Header::LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "copy-on-write store is too short",
            ));
        }

        let mut header = Header::default();
        read_at(&mut cow, 0, header.as_mut())?;
        let chunk_size = header.chunk_size()?;
        Self::validate_geometry(
            origin_bytes,
            cow_bytes,
            chunk_size,
            origin_block_size,
            cow_block_size,
            block_size,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let chunk_bytes = chunk_size.bytes();
        let allocation_size = chunk_size.len();
        let mut state = State::new(allocation_size)?;
        let cow_chunks = cow_bytes / chunk_bytes;

        let mut area = 0;
        loop {
            let chunk = state.metadata_chunk(area)?;
            if chunk >= cow_chunks {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot metadata walk leaves the store",
                ));
            }
            let mut bytes = buffer(allocation_size)?;
            read_at(&mut cow, chunk_size.offset(chunk)?, &mut bytes)?;
            state.buffer.copy_from_slice(&bytes);
            match state.absorb_area(area, cow_chunks) {
                Ok(true) => break,
                Ok(false) => {
                    area = area.checked_add(1).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot metadata area overflows",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Self::from_parts(
            origin,
            cow,
            origin_bytes,
            cow_bytes,
            chunk_size,
            block_size,
            state,
        ))
    }
}

impl<O, C> Merge for Layer<O, C>
where
    O: Write + Seek + SyncData,
    C: Read + Write + Seek + SyncData,
{
    fn merge(&mut self) -> io::Result<()> {
        SyncData::sync_data(self)?;
        let plan: Vec<_> = self.state_mut()?.exceptions().collect();
        let chunk_bytes = self.chunk_bytes();
        let origin_bytes = self.origin_bytes;
        let origin_chunks = origin_bytes.div_ceil(chunk_bytes);
        if plan.iter().any(|(origin, _)| *origin >= origin_chunks) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the store holds an exception outside the origin it is merged into",
            ));
        }

        let mut chunk = buffer(self.chunk_size.len())?;
        for &(origin, cow) in &plan {
            let cow_offset = self.chunk_size.offset(cow)?;
            read_at(self.cow_mut()?, cow_offset, &mut chunk)?;
            let origin_offset = self.chunk_size.offset(origin)?;
            let valid = usize::try_from((origin_bytes - origin_offset).min(chunk_bytes))
                .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
            self.origin_mut()?.seek(SeekFrom::Start(origin_offset))?;
            self.origin_mut()?.write_all(&chunk[..valid])?;
        }

        self.origin_mut()?.flush()?;
        self.origin_mut()?.sync_data()?;

        let per_area = chunk_bytes / State::EXCEPTION_LEN as u64;
        let areas = u64::try_from(plan.len())
            .unwrap_or(u64::MAX)
            .div_ceil(per_area)
            .max(1);
        chunk.fill(0);
        let retired = (|| {
            for area in (0..areas).rev() {
                let metadata = self.state_mut()?.metadata_chunk(area)?;
                let position = self.chunk_size.offset(metadata)?;
                self.cow_mut()?.seek(SeekFrom::Start(position))?;
                self.cow_mut()?.write_all(&chunk)?;
            }
            self.cow_mut()?.flush()?;
            self.cow_mut()?.sync_data()
        })();
        if let Err(error) = retired {
            return Err(self.fatal(error));
        }
        self.state_mut()?.clear();
        Ok(())
    }
}

impl<O, C> Compact for Layer<O, C>
where
    O: Read + Seek,
    C: Read + Seek,
{
    fn compact(&mut self, mut output: impl Write) -> io::Result<()> {
        self.ready()?;

        let chunk_bytes = self.chunk_bytes();
        let chunk_usize = self.chunk_size.len();
        let per_area = chunk_bytes / State::EXCEPTION_LEN as u64;
        let mut upper = buffer(chunk_usize)?;
        let mut lower = buffer(chunk_usize)?;
        let mut metadata = buffer(chunk_usize)?;
        let encoded = Header::new(self.chunk_size);
        upper[..Header::LEN].copy_from_slice(encoded.as_ref());
        output.write_all(&upper)?;

        let mut previous = None;
        let mut metadata_chunk = 1_u64;
        loop {
            metadata.fill(0);
            let mut retained = 0_u64;
            let mut exhausted = false;
            while retained < per_area {
                let Some((origin, cow)) = self.state_mut()?.next_exception(previous) else {
                    exhausted = true;
                    break;
                };
                previous = Some(origin);
                let origin_offset = self.chunk_size.offset(origin)?;
                if origin_offset >= self.origin_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the store holds an exception outside its origin",
                    ));
                }
                let valid = usize::try_from((self.origin_bytes - origin_offset).min(chunk_bytes))
                    .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
                let cow_offset = self.chunk_size.offset(cow)?;
                read_at(self.cow_mut()?, cow_offset, &mut upper)?;
                read_at(self.origin_mut()?, origin_offset, &mut lower[..valid])?;
                if upper[..valid] == lower[..valid] {
                    continue;
                }

                let destination = metadata_chunk
                    .checked_add(1)
                    .and_then(|chunk| chunk.checked_add(retained))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "compact geometry overflows")
                    })?;
                let slot = usize::try_from(retained)
                    .map_err(|_| io::Error::other("metadata slot exceeds usize"))?
                    * State::EXCEPTION_LEN;
                metadata[slot..slot + 8].copy_from_slice(&origin.to_le_bytes());
                metadata[slot + 8..slot + State::EXCEPTION_LEN]
                    .copy_from_slice(&destination.to_le_bytes());
                retained += 1;
            }

            output.write_all(&metadata)?;
            for slot in 0..retained {
                let offset = usize::try_from(slot)
                    .map_err(|_| io::Error::other("metadata slot exceeds usize"))?
                    * State::EXCEPTION_LEN;
                let origin = u64::from_le_bytes(
                    metadata[offset..offset + 8]
                        .try_into()
                        .map_err(|_| io::Error::other("metadata entry is truncated"))?,
                );
                let cow = self.state_mut()?.lookup(origin).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "snapshot exception disappeared")
                })?;
                let cow_offset = self.chunk_size.offset(cow)?;
                read_at(self.cow_mut()?, cow_offset, &mut upper)?;
                output.write_all(&upper)?;
            }

            if exhausted {
                return output.flush();
            }
            metadata_chunk = metadata_chunk.checked_add(per_area + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "compact geometry overflows")
            })?;
        }
    }
}

impl<O, C: Write + Seek> Layer<O, C> {
    fn put_cow(&mut self, chunk: u64, bytes: &[u8]) -> io::Result<()> {
        let position = self.chunk_size.offset(chunk)?;
        let cow = self.cow_mut()?;
        let result = cow
            .seek(SeekFrom::Start(position))
            .and_then(|_| cow.write_all(bytes));
        result.map_err(|error| self.fatal(error))
    }
}

impl<O, C: SyncData> Layer<O, C> {
    fn cow_barrier(&mut self) -> io::Result<()> {
        match self.cow_mut()?.sync_data() {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fatal(error)),
        }
    }
}

impl<O, C: Write + Seek + SyncData> Layer<O, C> {
    fn initialize(&mut self) -> io::Result<()> {
        let area = self.state_mut()?.current_metadata_chunk()?;
        let zeros = buffer(self.chunk_size.len())?;
        self.put_cow(area, &zeros)?;
        self.cow_barrier()?;

        let mut header = zeros;
        let encoded = Header::new(self.chunk_size);
        header[..Header::LEN].copy_from_slice(encoded.as_ref());
        self.put_cow(0, &header)?;
        let result = self.cow_mut()?.flush();
        result.map_err(|error| self.fatal(error))
    }

    fn publish_current(&mut self) -> io::Result<()> {
        if !self.state_mut()?.dirty {
            return Ok(());
        }
        self.cow_barrier()?;
        let chunk = self.state_mut()?.current_metadata_chunk()?;
        let bytes = self.state_mut()?.buffer.clone();
        self.put_cow(chunk, &bytes)?;
        self.state_mut()?.dirty = false;
        Ok(())
    }
}

impl<O: Read + Seek, C: Read + Seek> Layer<O, C> {
    fn read_chunk_prefix(&mut self, index: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.check_origin_chunk(index, false)?;
        let source = self.state_mut()?.lookup(index);
        if let Some(chunk) = source {
            let position = self.chunk_size.offset(chunk)?;
            read_at(self.cow_mut()?, position, bytes)
        } else {
            let position = self.chunk_size.offset(index)?;
            read_at(self.origin_mut()?, position, bytes)
        }
    }
}

impl<O: Read + Seek, C: Read + Write + Seek + SyncData> Layer<O, C> {
    fn write_chunk(&mut self, index: u64, within: usize, input: &[u8]) -> io::Result<()> {
        self.check_origin_chunk(index, true)?;
        let chunk_bytes = self.chunk_bytes();
        let chunk_usize = self.chunk_size.len();
        let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
            .map_err(|_| io::Error::other("snapshot chunk length exceeds usize"))?;

        if let Some(chunk) = self.state_mut()?.lookup(index) {
            if within == 0 && input.len() == chunk_usize {
                return self.put_cow(chunk, input);
            }
            let mut bytes = buffer(chunk_usize)?;
            let position = self.chunk_size.offset(chunk)?;
            read_at(self.cow_mut()?, position, &mut bytes)?;
            bytes[within..within + input.len()].copy_from_slice(input);
            return self.put_cow(chunk, &bytes);
        }

        let mut bytes = buffer(chunk_usize)?;
        let position = self.chunk_size.offset(index)?;
        read_at(self.origin_mut()?, position, &mut bytes[..valid])?;
        if bytes[within..within + input.len()] == *input {
            return Ok(());
        }
        let promoted = if within == 0 && input.len() == chunk_usize {
            input
        } else {
            bytes[within..within + input.len()].copy_from_slice(input);
            &bytes
        };

        let cow_chunks = self.cow_bytes / self.chunk_bytes();
        let chunk = self.state_mut()?.plan(cow_chunks)?;
        self.put_cow(chunk, promoted)?;
        let filled = match self.state_mut()?.commit(index, chunk) {
            Ok(filled) => filled,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Some(area) = filled {
            let terminator = self.state_mut()?.terminator_chunk()?;
            let zeros = buffer(self.chunk_size.len())?;
            self.put_cow(terminator, &zeros)?;
            self.cow_barrier()?;
            let metadata = self.state_mut()?.buffer.clone();
            self.put_cow(area, &metadata)?;
            self.state_mut()?.advance_area();
        }
        Ok(())
    }
}

impl<O: Read + Seek, C: Read + Seek> Read for Layer<O, C> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.ready()?;
        let origin_bytes = self.origin_bytes;
        if self.position >= origin_bytes {
            return Ok(0);
        }
        let chunk_bytes = self.chunk_bytes();
        let index = self.position / chunk_bytes;
        let within = usize::try_from(self.position % chunk_bytes)
            .map_err(|_| io::Error::other("snapshot position exceeds usize"))?;
        let remaining = usize::try_from(
            (origin_bytes - self.position).min(u64::try_from(output.len()).unwrap_or(u64::MAX)),
        )
        .map_err(|_| io::Error::other("snapshot read length exceeds usize"))?;
        let available = self.chunk_size.len() - within;
        let count = remaining.min(available);
        if within == 0 && count == self.chunk_size.len() {
            self.read_chunk_prefix(index, &mut output[..count])?;
        } else {
            let valid = usize::try_from((origin_bytes - index * chunk_bytes).min(chunk_bytes))
                .map_err(|_| io::Error::other("snapshot chunk length exceeds usize"))?;
            let mut scratch = buffer(self.chunk_size.len())?;
            self.read_chunk_prefix(index, &mut scratch[..valid])?;
            output[..count].copy_from_slice(&scratch[within..within + count]);
        }
        self.position +=
            u64::try_from(count).map_err(|_| io::Error::other("read count exceeds u64"))?;
        Ok(count)
    }
}

impl<O: Read + Seek, C: Read + Write + Seek + SyncData> Write for Layer<O, C> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.ready()?;
        let origin_bytes = self.origin_bytes;
        if self.position >= origin_bytes {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write starts beyond the layer",
            ));
        }
        let chunk_bytes = self.chunk_bytes();
        let chunk_usize = self.chunk_size.len();
        let index = self.position / chunk_bytes;
        let within = usize::try_from(self.position % chunk_bytes)
            .map_err(|_| io::Error::other("snapshot position exceeds usize"))?;
        let remaining = usize::try_from(
            (origin_bytes - self.position).min(u64::try_from(input.len()).unwrap_or(u64::MAX)),
        )
        .map_err(|_| io::Error::other("snapshot write length exceeds usize"))?;
        let count = remaining.min(chunk_usize - within);
        self.write_chunk(index, within, &input[..count])?;
        self.position +=
            u64::try_from(count).map_err(|_| io::Error::other("write count exceeds u64"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ready()?;
        self.publish_current()?;
        let result = self.cow_mut()?.flush();
        result.map_err(|error| self.fatal(error))
    }
}

impl<O, C> Seek for Layer<O, C> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.origin_bytes) + i128::from(delta),
        };
        self.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before the start of a layer",
            )
        })?;
        Ok(self.position)
    }
}

impl<O, C: Write + Seek + SyncData> SyncData for Layer<O, C> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.ready()?;
        self.publish_current()?;
        let result = self.cow_mut()?.flush();
        result.map_err(|error| self.fatal(error))?;
        let result = self.cow_mut()?.sync_data();
        result.map_err(|error| self.fatal(error))
    }
}
