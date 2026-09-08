// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "tokio")]
use std::future::Future;
#[cfg(feature = "tokio")]
use std::pin::Pin;

#[cfg(feature = "tokio")]
type PendingMerge<O, C> = Pin<Box<dyn Future<Output = io::Result<(O, C)>> + Send>>;

use crate::Layer;
use crate::chunk_size::EXCEPTION_LEN;
use crate::layer::state::buffer;

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

/// A pending merge of a snapshot store into its origin.
#[allow(missing_debug_implementations)]
#[must_use = "a merge does nothing until it is run"]
pub struct Merge<O, C> {
    layer: Option<Layer<O, C>>,
    plan: Vec<(u64, u64)>,
    chunk: Vec<u8>,
    #[cfg(feature = "tokio")]
    pending: Option<PendingMerge<O, C>>,
}

impl<O, C> Merge<O, C> {
    pub(crate) fn new(layer: Layer<O, C>) -> Self {
        Self {
            layer: Some(layer),
            plan: Vec::new(),
            chunk: Vec::new(),
            #[cfg(feature = "tokio")]
            pending: None,
        }
    }

    fn finished() -> io::Error {
        io::Error::other("this merge has already completed")
    }

    fn layer(&mut self) -> io::Result<&mut Layer<O, C>> {
        self.layer.as_mut().ok_or_else(Self::finished)
    }

    fn prepare(&mut self) -> io::Result<()> {
        self.plan = self.layer()?.loaded()?.exceptions().collect();
        self.chunk = buffer(self.layer()?.chunk_usize()?)?;
        Ok(())
    }

    fn preflight(&self) -> io::Result<()> {
        let layer = self.layer.as_ref().ok_or_else(Self::finished)?;
        let chunks = layer.origin_bytes.div_ceil(layer.chunk_bytes()?);
        if self.plan.iter().any(|(origin, _)| *origin >= chunks) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the store holds an exception outside the origin it is merged into",
            ));
        }
        Ok(())
    }

    fn areas(&self) -> io::Result<u64> {
        let layer = self.layer.as_ref().ok_or_else(Self::finished)?;
        let per_area = layer.chunk_bytes()? / EXCEPTION_LEN as u64;
        Ok(u64::try_from(self.plan.len())
            .unwrap_or(u64::MAX)
            .div_ceil(per_area)
            .max(1))
    }

    fn take_parts(&mut self) -> io::Result<(O, C)> {
        self.layer.take().ok_or_else(Self::finished)?.into_parts()
    }
}
