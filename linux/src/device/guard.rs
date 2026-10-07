// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{File, OpenOptions},
    io,
    ops::Deref,
};

#[cfg(feature = "tokio")]
use std::future::Future;

use super::Device;

/// An opt-in scope guard that immediately removes a device when dropped.
///
/// Guarding changes no kernel state. Normal scope exit attempts immediate
/// cleanup, while [`Defer::defer`] explicitly transitions to kernel-managed
/// deferred removal that survives process termination.
#[derive(Debug)]
pub struct Guard(Option<Device>);

impl Device {
    /// Wraps this device in an opt-in immediate-cleanup guard.
    #[must_use]
    pub fn guard(self) -> Guard {
        Guard(Some(self))
    }
}

impl Guard {
    /// Returns the persistent device without changing kernel state.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn disarm(mut self) -> Device {
        self.0.take().expect("guard is armed")
    }
}

/// Opens a guarded device for synchronous I/O and schedules deferred removal.
pub trait Defer: Sized {
    /// Opens the device and transitions it to kernel-managed deferred removal.
    ///
    /// The returned file keeps the device alive. Once its final holder closes,
    /// the kernel removes the device even if this process terminated without
    /// unwinding.
    ///
    /// # Errors
    ///
    /// Returns an open or deferred-removal error. Dropping the still-armed
    /// guard attempts immediate removal before returning either error; cleanup
    /// is best-effort because destructors cannot report failures.
    fn defer(self, options: &OpenOptions) -> io::Result<File>;
}

impl Defer for Guard {
    fn defer(mut self, options: &OpenOptions) -> io::Result<File> {
        let device = self.0.as_ref().expect("guard is armed");
        let file = options.open(device.node_path())?;

        if let Err(error) = device.clone().remove(true) {
            drop(file);
            return Err(error);
        }

        self.0.take();
        Ok(file)
    }
}

/// Opens a guarded device for Tokio I/O and schedules deferred removal.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub trait AsyncDefer: Sized {
    /// Asynchronously opens the device and transitions it to kernel-managed
    /// deferred removal.
    ///
    /// The returned file keeps the device alive. Once its final holder closes,
    /// the kernel removes the device even if this process terminated without
    /// unwinding. Opening the holder is asynchronous; the short removal ioctl
    /// and any rollback execute synchronously after the open completes.
    /// Cancelling while the holder is being opened drops the still-armed guard
    /// and attempts immediate removal.
    ///
    /// # Errors
    ///
    /// Returns an open or deferred-removal error. Dropping the still-armed
    /// guard attempts immediate removal before returning either error; cleanup
    /// is best-effort because destructors cannot report failures.
    fn defer(
        self,
        options: &tokio::fs::OpenOptions,
    ) -> impl Future<Output = io::Result<tokio::fs::File>> + Send;
}

#[cfg(feature = "tokio")]
impl AsyncDefer for Guard {
    fn defer(
        mut self,
        options: &tokio::fs::OpenOptions,
    ) -> impl Future<Output = io::Result<tokio::fs::File>> + Send {
        let options = options.clone();
        async move {
            let device = self.0.as_ref().expect("guard is armed");
            let file = options.open(device.node_path()).await?;

            if let Err(error) = device.clone().remove(true) {
                drop(file);
                return Err(error);
            }

            self.0.take();
            Ok(file)
        }
    }
}

impl Deref for Guard {
    type Target = Device;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("guard is armed")
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(device) = self.0.take() {
            let _ = device.remove(false);
        }
    }
}
