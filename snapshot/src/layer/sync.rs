// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::{ChunkSize, SyncData};

use super::state::{State, buffer};
use super::{Layer, Load};

fn offset(index: u64, chunk_bytes: u64) -> io::Result<u64> {
    index
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "snapshot offset overflows"))
}

fn read_at<R: Read + Seek>(reader: &mut R, position: u64, bytes: &mut [u8]) -> io::Result<()> {
    reader.seek(SeekFrom::Start(position))?;
    reader.read_exact(bytes)
}

fn write_at<W: Write + Seek>(writer: &mut W, position: u64, bytes: &[u8]) -> io::Result<()> {
    writer.seek(SeekFrom::Start(position))?;
    writer.write_all(bytes)
}

impl<O, C: Read + Seek> Layer<O, C> {
    pub(crate) fn load(&mut self) -> io::Result<()> {
        match self.load {
            Load::Ready => return Ok(()),
            Load::Failed => return Err(Self::poisoned()),
            Load::Create => {
                self.state = Some(State::new(self.chunk_usize()?)?);
                self.load = Load::Ready;
                return Ok(());
            }
            Load::Open => {}
        }

        let mut header = [0; ChunkSize::HEADER_LEN];
        read_at(self.cow_mut()?, 0, &mut header)?;
        let parsed_size = match ChunkSize::from_header(&header) {
            Ok(size) => size,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Err(error) = Self::validate_cow(self.cow_bytes, parsed_size) {
            return Err(self.fatal(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        self.chunk_size = Some(parsed_size);
        let chunk_bytes = self.chunk_bytes()?;
        let allocation_size = self.chunk_usize()?;
        self.state = Some(State::new(allocation_size)?);
        let cow_chunks = self.cow_chunks()?;

        let mut area = 0;
        loop {
            let chunk = self.loaded()?.metadata_chunk(area)?;
            if chunk >= cow_chunks {
                return Err(self.fatal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot metadata walk leaves the store",
                )));
            }
            let mut bytes = buffer(allocation_size)?;
            read_at(self.cow_mut()?, offset(chunk, chunk_bytes)?, &mut bytes)?;
            self.loaded()?.buffer_mut().copy_from_slice(&bytes);
            match self.loaded()?.absorb_area(area, cow_chunks) {
                Ok(true) => break,
                Ok(false) => {
                    area = area.checked_add(1).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot metadata area overflows",
                        )
                    })?;
                }
                Err(error) => return Err(self.fatal(error)),
            }
        }
        self.load = Load::Ready;
        Ok(())
    }
}

impl<O, C: Write + Seek + SyncData> Layer<O, C> {
    fn put_cow(&mut self, chunk: u64, bytes: &[u8]) -> io::Result<()> {
        let position = offset(chunk, self.chunk_bytes()?)?;
        let result = write_at(self.cow_mut()?, position, bytes);
        result.map_err(|error| self.fatal(error))
    }

    fn cow_barrier(&mut self) -> io::Result<()> {
        match self.cow_mut()?.sync_data() {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fatal(error)),
        }
    }

    pub(crate) fn prepare(&mut self) -> io::Result<()> {
        if !self.fresh {
            return Ok(());
        }
        let area = self.loaded()?.current_metadata_chunk()?;
        let zeros = buffer(self.chunk_usize()?)?;
        self.put_cow(area, &zeros)?;
        self.cow_barrier()?;

        let mut header = zeros;
        let encoded = self
            .chunk_size
            .ok_or_else(|| io::Error::other("snapshot chunk size is not loaded"))?
            .header();
        header[..encoded.len()].copy_from_slice(&encoded);
        self.put_cow(0, &header)?;
        self.fresh = false;
        Ok(())
    }

    fn publish_current(&mut self) -> io::Result<()> {
        if !self.loaded()?.is_dirty() {
            return Ok(());
        }
        self.cow_barrier()?;
        let chunk = self.loaded()?.current_metadata_chunk()?;
        let bytes = self.loaded()?.buffer().to_vec();
        self.put_cow(chunk, &bytes)?;
        self.loaded()?.published();
        Ok(())
    }
}

impl<O: Read + Seek, C: Read + Seek> Layer<O, C> {
    fn read_chunk_prefix(&mut self, index: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.check_origin_chunk(index, false)?;
        let chunk_bytes = self.chunk_bytes()?;
        let source = self.loaded()?.lookup(index);
        match source {
            Some(chunk) => read_at(self.cow_mut()?, offset(chunk, chunk_bytes)?, bytes),
            None => read_at(self.origin_mut()?, offset(index, chunk_bytes)?, bytes),
        }
    }
}

impl<O: Read + Seek, C: Read + Write + Seek + SyncData> Layer<O, C> {
    fn write_chunk(&mut self, index: u64, bytes: &[u8]) -> io::Result<()> {
        self.check_origin_chunk(index, true)?;
        self.prepare()?;
        let cow_chunks = self.cow_chunks()?;
        let (chunk, fresh) = self.loaded()?.plan(index, cow_chunks)?;
        self.put_cow(chunk, bytes)?;
        let filled = match self.loaded()?.commit(index, chunk, fresh) {
            Ok(filled) => filled,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Some(area) = filled {
            let terminator = self.loaded()?.terminator_chunk()?;
            let zeros = buffer(self.chunk_usize()?)?;
            self.put_cow(terminator, &zeros)?;
            self.cow_barrier()?;
            let metadata = self.loaded()?.buffer().to_vec();
            self.put_cow(area, &metadata)?;
            self.loaded()?.advance_area();
        }
        Ok(())
    }
}

impl<O: Read + Seek, C: Read + Seek> Read for Layer<O, C> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.origin_bytes {
            return Ok(0);
        }
        self.load()?;
        let chunk_bytes = self.chunk_bytes()?;
        let index = self.position / chunk_bytes;
        let within = usize::try_from(self.position % chunk_bytes)
            .map_err(|_| io::Error::other("snapshot position exceeds usize"))?;
        let remaining = usize::try_from(
            (self.origin_bytes - self.position)
                .min(u64::try_from(output.len()).unwrap_or(u64::MAX)),
        )
        .map_err(|_| io::Error::other("snapshot read length exceeds usize"))?;
        let available = self.chunk_usize()? - within;
        let count = remaining.min(available);
        if within == 0 && count == self.chunk_usize()? {
            self.read_chunk_prefix(index, &mut output[..count])?;
        } else {
            let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
                .map_err(|_| io::Error::other("snapshot chunk length exceeds usize"))?;
            let mut scratch = buffer(self.chunk_usize()?)?;
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
        if self.position >= self.origin_bytes {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write starts beyond the layer",
            ));
        }
        self.load()?;
        let chunk_bytes = self.chunk_bytes()?;
        let chunk_usize = self.chunk_usize()?;
        let index = self.position / chunk_bytes;
        let within = usize::try_from(self.position % chunk_bytes)
            .map_err(|_| io::Error::other("snapshot position exceeds usize"))?;
        let remaining = usize::try_from(
            (self.origin_bytes - self.position).min(u64::try_from(input.len()).unwrap_or(u64::MAX)),
        )
        .map_err(|_| io::Error::other("snapshot write length exceeds usize"))?;
        let count = remaining.min(chunk_usize - within);
        if within == 0 && count == chunk_usize {
            self.write_chunk(index, &input[..count])?;
        } else {
            let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
                .map_err(|_| io::Error::other("snapshot chunk length exceeds usize"))?;
            let mut scratch = buffer(chunk_usize)?;
            self.read_chunk_prefix(index, &mut scratch[..valid])?;
            scratch[within..within + count].copy_from_slice(&input[..count]);
            self.write_chunk(index, &scratch)?;
        }
        self.position +=
            u64::try_from(count).map_err(|_| io::Error::other("write count exceeds u64"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.load()?;
        self.prepare()?;
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

impl<O: Read + Seek, C: Read + Write + Seek + SyncData> SyncData for Layer<O, C> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.flush()?;
        let result = self.cow_mut()?.sync_data();
        result.map_err(|error| self.fatal(error))
    }
}
