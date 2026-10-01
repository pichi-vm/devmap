// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io,
    ops::Deref,
};

use super::Device;

/// An opt-in scope guard that immediately removes a device when dropped.
///
/// Guarding changes no kernel state. Normal scope exit attempts immediate
/// cleanup, while [`Guard::defer`] explicitly transitions to kernel-managed
/// deferred removal that survives process termination.
#[derive(Debug)]
pub struct Guard(Option<Device>);

#[derive(Debug)]
struct RollbackError {
    operation: io::Error,
    cleanup: io::Error,
}

impl fmt::Display for RollbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; immediate cleanup also failed: {}",
            self.operation, self.cleanup
        )
    }
}

impl Error for RollbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.operation)
    }
}

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

    /// Opens the device and transitions it to kernel-managed deferred removal.
    ///
    /// The returned file keeps the device alive. Once its final holder closes,
    /// the kernel removes the device even if this process terminated without
    /// unwinding.
    ///
    /// # Errors
    ///
    /// Returns an open or deferred-removal error. The guard attempts immediate
    /// removal before returning any error; if rollback also fails, the returned
    /// error reports both failures.
    #[allow(clippy::missing_panics_doc)]
    pub fn defer(mut self, options: &OpenOptions) -> io::Result<File> {
        let device = self.0.as_ref().expect("guard is armed");
        let file = match options.open(device.node_path()) {
            Ok(file) => file,
            Err(error) => return Err(self.rollback(error)),
        };

        if let Err(error) = device.remove_now(true) {
            drop(file);
            return Err(self.rollback(error));
        }

        self.0.take();
        Ok(file)
    }

    fn rollback(&mut self, operation: io::Error) -> io::Error {
        let kind = operation.kind();
        let device = self.0.take().expect("guard is armed");
        match device.remove(false) {
            Ok(()) => operation,
            Err(cleanup) => io::Error::new(kind, RollbackError { operation, cleanup }),
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
