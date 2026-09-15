// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::num::{NonZeroU32, NonZeroU64};

use crate::chunk_size::ChunkSize;
use state::State;

#[cfg(feature = "tokio")]
mod r#async;
pub(crate) mod state;
mod sync;

/// A seekable copy-on-write view of an origin and a persistent COW store.
///
/// The layer's length is the origin's length. Reads select the newest value
/// from either endpoint; writes leave the origin unchanged and store complete
/// changed chunks in the COW. A write at or beyond the end returns
/// [`io::ErrorKind::WriteZero`]. Seeking beyond the end is allowed.
/// Before allocating a new COW chunk, a write is compared with the origin.
/// Matching bytes are accepted without allocating or writing to the COW;
/// this applies to both full-chunk and partial-chunk writes. Existing COW
/// chunks are updated directly, even when the new bytes match the origin.
///
/// [`std::io::Write::flush`] completes pending writes without promising their
/// durability. Call [`devmap_core::traits::std::SyncData::sync_data`] after
/// flushing when completed writes must survive loss of volatile caches.
/// Dropping a layer performs neither operation. After an error that leaves the
/// COW's consistency uncertain, subsequent operations return an error.
#[allow(missing_debug_implementations)]
pub struct Layer<O, C> {
    pub(crate) origin: Option<O>,
    pub(crate) cow: Option<C>,
    pub(crate) origin_bytes: u64,
    pub(crate) cow_bytes: u64,
    pub(crate) position: u64,
    pub(crate) chunk_size: ChunkSize,
    block_size: NonZeroU32,
    pub(crate) state: Option<State>,
    failed: bool,
    #[cfg(feature = "tokio")]
    pending: Option<r#async::Pending<O, C>>,
}

impl<O, C> Layer<O, C> {
    pub(super) fn from_parts(
        origin: O,
        cow: C,
        origin_bytes: u64,
        cow_bytes: u64,
        chunk_size: ChunkSize,
        block_size: NonZeroU32,
        state: State,
    ) -> Self {
        Self {
            origin: Some(origin),
            cow: Some(cow),
            origin_bytes,
            cow_bytes,
            position: 0,
            chunk_size,
            block_size,
            state: Some(state),
            failed: false,
            #[cfg(feature = "tokio")]
            pending: None,
        }
    }

    fn validate_geometry(
        origin_bytes: u64,
        cow_bytes: u64,
        chunk_size: ChunkSize,
        origin_block_size: NonZeroU32,
        cow_block_size: NonZeroU32,
        block_size: NonZeroU32,
    ) -> io::Result<()> {
        let bytes = chunk_size.bytes();
        if bytes % u64::from(origin_block_size.get()) != 0
            || bytes % u64::from(cow_block_size.get()) != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size must be a multiple of both endpoint block sizes",
            ));
        }
        if cow_bytes % bytes != 0 || cow_bytes < bytes.saturating_mul(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy-on-write store length must be a whole number of chunks and hold header metadata",
            ));
        }
        if origin_bytes % u64::from(block_size.get()) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "origin length is not a multiple of the layer block size",
            ));
        }
        Ok(())
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
        self.failed = true;
        error
    }

    pub(crate) fn ready(&self) -> io::Result<()> {
        if self.failed {
            Err(Self::poisoned())
        } else {
            Ok(())
        }
    }

    pub(crate) fn state_mut(&mut self) -> io::Result<&mut State> {
        self.state.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "an asynchronous layer operation is in progress",
            )
        })
    }

    pub(crate) fn chunk_bytes(&self) -> u64 {
        self.chunk_size.bytes()
    }

    pub(crate) fn check_origin_chunk(&self, index: u64, writing: bool) -> io::Result<()> {
        let start = self.chunk_size.offset(index)?;
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

    pub(crate) fn combined_block_size(
        origin: NonZeroU32,
        cow: NonZeroU32,
    ) -> io::Result<NonZeroU32> {
        let origin = origin.get();
        let cow = cow.get();
        let mut left = origin;
        let mut right = cow;
        while right != 0 {
            let remainder = left % right;
            left = right;
            right = remainder;
        }
        let combined = u64::from(origin / left)
            .checked_mul(u64::from(cow))
            .and_then(NonZeroU64::new)
            .ok_or_else(|| io::Error::other("combined block size overflows"))?;
        NonZeroU32::try_from(combined)
            .map_err(|_| io::Error::other("combined block size exceeds u32"))
    }
}
