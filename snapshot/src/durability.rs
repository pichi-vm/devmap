// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "tokio")]
use std::future::Future;

/// Makes previously completed data writes nonvolatile.
///
/// Unlike [`io::Write::flush`], this is a persistence barrier. Implement it
/// only for storage whose completed writes can be made durable.
pub trait SyncData {
    /// Waits until previously completed data writes are on stable storage.
    fn sync_data(&mut self) -> io::Result<()>;
}

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

/// Asynchronous counterpart of [`SyncData`].
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait AsyncSyncData {
    /// Waits until previously completed data writes are on stable storage.
    fn sync_data(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

#[cfg(feature = "tokio")]
impl AsyncSyncData for tokio::fs::File {
    async fn sync_data(&mut self) -> io::Result<()> {
        tokio::fs::File::sync_data(self).await
    }
}

#[cfg(feature = "tokio")]
impl<T: AsyncSyncData + Send + ?Sized> AsyncSyncData for &mut T {
    async fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self).await
    }
}

#[cfg(feature = "tokio")]
impl<T: AsyncSyncData + Send + ?Sized> AsyncSyncData for Box<T> {
    async fn sync_data(&mut self) -> io::Result<()> {
        T::sync_data(self).await
    }
}
