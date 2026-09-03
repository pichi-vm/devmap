// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Seek, SeekFrom, Write};

#[derive(Debug, Default)]
pub(super) struct SeekSink {
    position: u64,
}

impl Write for SeekSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.position = self
            .position
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sink position overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SeekSink {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(position) => position,
            SeekFrom::Current(offset) if offset >= 0 => self
                .position
                .checked_add(offset.cast_unsigned())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "sink position overflow")
                })?,
            SeekFrom::Current(offset) => self
                .position
                .checked_sub(offset.unsigned_abs())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "cannot seek before start of sink",
                    )
                })?,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "sink has no end",
                ));
            }
        };
        Ok(self.position)
    }
}
