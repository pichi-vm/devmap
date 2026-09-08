// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::{ChunkSize, Layer, SyncData};

/// What a conversion produced.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conversion {
    /// The length of the store in bytes.
    pub cow_bytes: u64,
    /// The number of nonzero chunks stored as exceptions.
    pub exception_count: u64,
}

#[derive(Debug)]
struct ZeroOrigin {
    position: u64,
    length: u64,
}

impl Read for ZeroOrigin {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(
            (self.length - self.position.min(self.length))
                .min(u64::try_from(output.len()).unwrap_or(u64::MAX)),
        )
        .map_err(|_| io::Error::other("zero origin length exceeds usize"))?;
        output[..count].fill(0);
        self.position +=
            u64::try_from(count).map_err(|_| io::Error::other("read count exceeds u64"))?;
        Ok(count)
    }
}

impl Seek for ZeroOrigin {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek before zero origin"))?;
        Ok(self.position)
    }
}

/// Writes a raw image into a sparse persistent COW over a zero origin.
///
/// A partial final image chunk is zero-padded. The returned store has been
/// passed through [`SyncData::sync_data`].
pub fn convert<R: Read, W: Read + Write + Seek + SyncData>(
    input: R,
    input_len: u64,
    mut cow: W,
    chunk_size: ChunkSize,
) -> io::Result<Conversion> {
    let chunk_bytes = chunk_size.bytes().get();
    let origin_chunks = input_len.div_ceil(chunk_bytes);
    let origin_bytes = origin_chunks
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "origin length overflows"))?;
    let cow_bytes = chunk_size
        .cow_chunks(origin_chunks)?
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "store length overflows"))?;
    extend(&mut cow, cow_bytes)?;
    let origin = ZeroOrigin {
        position: 0,
        length: origin_bytes,
    };
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, chunk_size)?;
    let chunk_len = usize::try_from(chunk_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "chunk size exceeds usize"))?;
    let mut chunk = vec![0; chunk_len];
    let mut input = input.take(input_len);
    let mut position = 0;
    loop {
        chunk.fill(0);
        let filled = fill(&mut input, &mut chunk)?;
        if filled == 0 {
            break;
        }
        if chunk.iter().any(|byte| *byte != 0) {
            layer.seek(SeekFrom::Start(position))?;
            layer.write_all(&chunk)?;
        }
        position += chunk_bytes;
        if filled < chunk_len {
            break;
        }
    }
    layer.sync_data()?;
    Ok(Conversion {
        cow_bytes,
        exception_count: layer.exception_count().unwrap_or_default(),
    })
}

/// Hole-aware [`convert`] for an open file or block device.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "linux", target_os = "macos"))))]
pub fn convert_sparse<W: Read + Write + Seek + SyncData>(
    input: &std::fs::File,
    input_len: u64,
    mut cow: W,
    chunk_size: ChunkSize,
) -> io::Result<Conversion> {
    use std::os::unix::fs::FileExt as _;

    let chunk_bytes = chunk_size.bytes().get();
    let origin_chunks = input_len.div_ceil(chunk_bytes);
    let origin_bytes = origin_chunks
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "origin length overflows"))?;
    let cow_bytes = chunk_size
        .cow_chunks(origin_chunks)?
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "store length overflows"))?;
    extend(&mut cow, cow_bytes)?;
    let origin = ZeroOrigin {
        position: 0,
        length: origin_bytes,
    };
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, chunk_size)?;
    let mut chunk = vec![
        0;
        usize::try_from(chunk_bytes).map_err(|_| io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk size exceeds usize"
        ))?
    ];

    let mut position = 0;
    let mut data_start = 0;
    let mut data_end = 0;
    while position < input_len {
        if position >= data_end {
            match rustix::fs::seek(input, rustix::fs::SeekFrom::Data(position)) {
                Ok(start) => {
                    data_start = start;
                    data_end = rustix::fs::seek(input, rustix::fs::SeekFrom::Hole(start))
                        .map_err(io::Error::from)?;
                }
                Err(rustix::io::Errno::NXIO) => break,
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOTSUP) => {
                    data_start = position;
                    data_end = input_len;
                }
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        let end = position.saturating_add(chunk_bytes).min(input_len);
        if end > data_start {
            chunk.fill(0);
            let want = usize::try_from(end - position)
                .map_err(|_| io::Error::other("chunk length exceeds usize"))?;
            input.read_exact_at(&mut chunk[..want], position)?;
            if chunk.iter().any(|byte| *byte != 0) {
                layer.seek(SeekFrom::Start(position))?;
                layer.write_all(&chunk)?;
            }
        }
        position += chunk_bytes;
    }
    layer.sync_data()?;
    Ok(Conversion {
        cow_bytes,
        exception_count: layer.exception_count().unwrap_or_default(),
    })
}

fn extend<W: Write + Seek>(cow: &mut W, length: u64) -> io::Result<()> {
    if cow.seek(SeekFrom::End(0))? < length {
        cow.seek(SeekFrom::Start(length - 1))?;
        cow.write_all(&[0])?;
    }
    Ok(())
}

fn fill<R: Read>(input: &mut R, output: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < output.len() {
        match input.read(&mut output[filled..])? {
            0 => break,
            count => filled += count,
        }
    }
    Ok(filled)
}
