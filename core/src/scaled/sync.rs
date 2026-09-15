// SPDX-License-Identifier: Apache-2.0

use std::io::{self, IoSlice, IoSliceMut, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

use super::Scaled;
use crate::traits::std::{Geometry, SyncData};

impl<T: Read> Read for Scaled<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.inner.read(output)
    }

    fn read_vectored(&mut self, output: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(output)
    }
}

impl<T: Write> Write for Scaled<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.inner.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn write_vectored(&mut self, input: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(input)
    }
}

impl<T: Seek> Seek for Scaled<T> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

impl<T: SyncData> SyncData for Scaled<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

impl<T: Geometry> Geometry for Scaled<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> io::Result<u64> {
        let multiplier = u64::from(self.multiplier.get());
        let count = self.inner.count()?;
        if count % multiplier != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "underlying block count is incompatible with the scaled block size",
            ));
        }
        Ok(count / multiplier)
    }
}
