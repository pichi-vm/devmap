// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::ChunkSize;
use crate::merge::Merge;
use state::State;

#[cfg(feature = "tokio")]
mod r#async;
pub(crate) mod state;
mod sync;

/// A seekable byte stream presenting a snapshot over an origin.
///
/// Reads without an exception come from `origin`; writes allocate a complete
/// chunk in `cow` and leave the origin unchanged. The devices are addressed
/// through the standard synchronous I/O traits, or Tokio's matching traits
/// when the `tokio` feature is enabled.
///
/// [`io::Write::flush`] publishes staged exception metadata and flushes
/// transport buffers. [`crate::SyncData::sync_data`] additionally makes all
/// completed layer writes durable. Dropping a layer performs neither step.
#[allow(missing_debug_implementations)]
pub struct Layer<O, C> {
    pub(crate) origin: Option<O>,
    pub(crate) cow: Option<C>,
    pub(crate) origin_bytes: u64,
    pub(crate) cow_bytes: u64,
    pub(crate) position: u64,
    pub(crate) chunk_size: Option<ChunkSize>,
    pub(crate) state: Option<State>,
    load: Load,
    fresh: bool,
    #[cfg(feature = "tokio")]
    pending: Option<r#async::Pending<O, C>>,
}

#[derive(Clone, Copy)]
pub(super) enum Load {
    Create,
    Open,
    Ready,
    Failed,
}

impl<O, C> Layer<O, C> {
    /// Creates an empty store without performing I/O.
    ///
    /// `origin_bytes` is the length exposed by the layer. `cow_bytes` must be
    /// a multiple of `chunk_size` and include room for the header, metadata,
    /// data, and terminating metadata area.
    pub fn create(
        origin: O,
        cow: C,
        origin_bytes: u64,
        cow_bytes: u64,
        chunk_size: ChunkSize,
    ) -> io::Result<Self> {
        Self::validate_cow(cow_bytes, chunk_size)?;
        Ok(Self {
            origin: Some(origin),
            cow: Some(cow),
            origin_bytes,
            cow_bytes,
            position: 0,
            chunk_size: Some(chunk_size),
            state: None,
            load: Load::Create,
            fresh: true,
            #[cfg(feature = "tokio")]
            pending: None,
        })
    }

    /// Opens an existing store without performing I/O.
    ///
    /// The first operation reads the header to discover the chunk size and
    /// recover the exception list.
    pub fn open(origin: O, cow: C, origin_bytes: u64, cow_bytes: u64) -> io::Result<Self> {
        if cow_bytes < ChunkSize::HEADER_LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy-on-write store is too short",
            ));
        }
        Ok(Self {
            origin: Some(origin),
            cow: Some(cow),
            origin_bytes,
            cow_bytes,
            position: 0,
            chunk_size: None,
            state: None,
            load: Load::Open,
            fresh: false,
            #[cfg(feature = "tokio")]
            pending: None,
        })
    }

    fn validate_cow(cow_bytes: u64, chunk_size: ChunkSize) -> io::Result<()> {
        let bytes = chunk_size.bytes().get();
        if cow_bytes % bytes != 0 || cow_bytes < bytes.saturating_mul(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy-on-write store length must be a whole number of chunks and hold header metadata",
            ));
        }
        Ok(())
    }

    /// Returns the layer's length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.origin_bytes
    }

    /// Returns whether the layer exposes no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.origin_bytes == 0
    }

    /// Returns the chunk size once it is known.
    ///
    /// A newly created layer knows it immediately. An opened layer learns it
    /// when its first I/O operation reads the store header.
    #[must_use]
    pub const fn chunk_size(&self) -> Option<ChunkSize> {
        self.chunk_size
    }

    /// Returns the recovered number of exceptions, or `None` before an opened
    /// store has been read.
    #[must_use]
    pub fn exception_count(&self) -> Option<u64> {
        self.state.as_ref().map(State::exception_count)
    }

    /// Returns a merger that copies this store into its origin.
    pub fn merge(self) -> Merge<O, C> {
        Merge::new(self)
    }

    pub(crate) fn into_parts(self) -> io::Result<(O, C)> {
        let origin = self.origin.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous layer operation is in progress",
            )
        })?;
        let cow = self.cow.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous layer operation is in progress",
            )
        })?;
        Ok((origin, cow))
    }

    pub(crate) fn origin_mut(&mut self) -> io::Result<&mut O> {
        self.origin.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous layer operation is in progress",
            )
        })
    }

    pub(crate) fn cow_mut(&mut self) -> io::Result<&mut C> {
        self.cow.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous layer operation is in progress",
            )
        })
    }

    pub(crate) fn poisoned() -> io::Error {
        io::Error::other("cannot use a layer after a store write failed")
    }

    pub(crate) fn fatal(&mut self, error: io::Error) -> io::Error {
        self.load = Load::Failed;
        error
    }

    pub(crate) fn loaded(&mut self) -> io::Result<&mut State> {
        self.state
            .as_mut()
            .ok_or_else(|| io::Error::other("the exception store is not loaded"))
    }

    pub(crate) fn chunk_bytes(&self) -> io::Result<u64> {
        self.chunk_size
            .map(|size| size.bytes().get())
            .ok_or_else(|| io::Error::other("the snapshot chunk size is not loaded"))
    }

    pub(crate) fn chunk_usize(&self) -> io::Result<usize> {
        usize::try_from(self.chunk_bytes()?)
            .map_err(|_| io::Error::other("snapshot chunk size exceeds usize"))
    }

    pub(crate) fn cow_chunks(&self) -> io::Result<u64> {
        Ok(self.cow_bytes / self.chunk_bytes()?)
    }

    pub(crate) fn check_origin_chunk(&self, index: u64, writing: bool) -> io::Result<()> {
        let start = index.checked_mul(self.chunk_bytes()?).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot offset overflows")
        })?;
        if start < self.origin_bytes {
            return Ok(());
        }
        Err(io::Error::new(
            if writing {
                io::ErrorKind::WriteZero
            } else {
                io::ErrorKind::UnexpectedEof
            },
            "chunk index is outside the layer's origin",
        ))
    }
}
