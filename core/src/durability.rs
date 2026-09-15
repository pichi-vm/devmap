// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "tokio")]
use std::future::Future;
#[cfg(feature = "tokio")]
use std::pin::Pin;

use crate::traits::std::SyncData;

impl SyncData for std::fs::File {
    fn sync_data(&mut self) -> io::Result<()> {
        std::fs::File::sync_data(self)
    }
}

impl<T> SyncData for std::io::Cursor<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: SyncData + ?Sized> SyncData for &mut T {
    fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self)
    }
}

impl<T: SyncData + ?Sized> SyncData for Box<T> {
    fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self)
    }
}

#[cfg(feature = "tokio")]
impl crate::traits::tokio::SyncData for tokio::fs::File {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(tokio::fs::File::sync_data(self))
    }
}

#[cfg(feature = "tokio")]
impl<T> crate::traits::tokio::SyncData for std::io::Cursor<T> {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(feature = "tokio")]
impl<T: crate::traits::tokio::SyncData + ?Sized> crate::traits::tokio::SyncData for &mut T {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        T::sync_data(self)
    }
}

#[cfg(feature = "tokio")]
impl<T: crate::traits::tokio::SyncData + ?Sized> crate::traits::tokio::SyncData for Box<T> {
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        T::sync_data(self)
    }
}
