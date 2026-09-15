// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, ready};
use std::io;
use std::num::NonZeroU32;
use std::pin::Pin;

use tokio::io::{AsyncSeekExt as _, SeekFrom};

use super::{Region, Scaled};
use crate::traits::tokio::Geometry;

const BYTE: NonZeroU32 = NonZeroU32::MIN;

impl Geometry for tokio::fs::File {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        #[cfg(target_os = "linux")]
        {
            crate::uapi::block_size(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(BYTE)
        }
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(async move {
            let position = self.stream_position().await?;
            let length = self.seek(SeekFrom::End(0)).await?;
            self.seek(SeekFrom::Start(position)).await?;
            let block_size = u64::from(self.block_size()?.get());
            if length % block_size != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "device length is not a multiple of its block size",
                ));
            }
            Ok(length / block_size)
        })
    }
}

impl<T: AsRef<[u8]>> Geometry for std::io::Cursor<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(BYTE)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        let count = u64::try_from(self.get_ref().as_ref().len())
            .map_err(|_| io::Error::other("device length exceeds u64"));
        Box::pin(ready(count))
    }
}

impl<T: Geometry + ?Sized> Geometry for &mut T {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        T::count(self)
    }
}

impl<T: Geometry + ?Sized> Geometry for Box<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        T::block_size(self)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        T::count(self)
    }
}

impl<T: Geometry> Geometry for Scaled<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.reported_block_size())
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        let multiplier = u64::from(self.multiplier().get());
        let count = self.as_mut().count();
        Box::pin(async move {
            let count = count.await?;
            if count % multiplier != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "underlying block count is incompatible with the scaled block size",
                ));
            }
            Ok(count / multiplier)
        })
    }
}

impl<T> Geometry for Region<T> {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(self.reported_block_size())
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(ready(Ok(self.reported_count())))
    }
}
