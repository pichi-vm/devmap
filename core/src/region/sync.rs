// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

use super::Region;
use crate::traits::std::{Geometry, SyncData};

impl<T> Region<T> {
    pub(crate) fn from_sync(
        mut inner: T,
        start: u64,
        count: u64,
        device_count: u64,
        block_size: NonZeroU32,
    ) -> io::Result<Self>
    where
        T: Seek,
    {
        let (start, length) = Self::layout(start, count, device_count, block_size)?;
        inner.seek(SeekFrom::Start(start))?;
        Ok(Self {
            inner,
            start,
            length,
            count,
            block_size,
            position: 0,
            #[cfg(feature = "tokio")]
            pending_seek: None,
        })
    }
}

impl<T: Read> Read for Region<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let limit = usize::try_from(remaining.min(output.len() as u64))
            .map_err(|_| io::Error::other("device slice read length exceeds usize"))?;
        if limit == 0 {
            return Ok(0);
        }
        let count = self.inner.read(&mut output[..limit])?;
        self.position = self.position.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "device slice position overflows",
            )
        })?;
        Ok(count)
    }
}

impl<T: Write> Write for Region<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let limit = usize::try_from(remaining.min(input.len() as u64))
            .map_err(|_| io::Error::other("device slice write length exceeds usize"))?;
        if limit == 0 {
            return Ok(0);
        }
        let count = self.inner.write(&input[..limit])?;
        self.position = self.position.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "device slice position overflows",
            )
        })?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<T: Seek> Seek for Region<T> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = self.seek_position(seek)?;
        let underlying = self.start.checked_add(position).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "device slice seek overflows")
        })?;
        self.inner.seek(SeekFrom::Start(underlying))?;
        self.position = position;
        Ok(position)
    }
}

impl<T: SyncData> SyncData for Region<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

impl<T> Geometry for Region<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> io::Result<u64> {
        Ok(self.count)
    }
}
