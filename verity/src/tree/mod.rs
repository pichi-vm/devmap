// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "futures-io")]
use state::PendingBlock;
use state::State;

use crate::Verified;

#[cfg(feature = "futures-io")]
mod r#async;
mod state;
mod sync;

/// Writes a dm-verity hash tree to a seekable output.
///
/// Write the number of data blocks declared by the superblock. The final block
/// may be short; `flush` pads it with zeroes. Before the final block, `flush`
/// succeeds only at a data-block boundary. No more data can be written after
/// the final block is complete. If the final block is short, the backing data
/// device must contain the same zero padding.
///
/// Call [`digest`](Self::digest) after the final `flush`. Dropping the writer
/// does not flush it. The writer cannot be used after an output error.
#[allow(missing_debug_implementations)]
#[must_use = "dropping a tree writer does not finish the hash tree"]
pub struct TreeWriter<W> {
    output: W,
    tree: State,
    output_range: Option<OutputRange>,
    phase: Phase,
}

impl<W> TreeWriter<W> {
    /// Creates a tree writer at the output's current position.
    ///
    /// This writes only the hash tree. Write the [`Unverified`](crate::Unverified)
    /// superblock and its [`padding`](Verified::padding) first. Creating the
    /// writer performs no I/O.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] if the feature for the selected
    /// hash algorithm is not enabled.
    pub fn new(output: W, superblock: Verified) -> io::Result<Self> {
        let hasher = superblock.algorithm().hasher().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "hash algorithm support is not enabled",
            )
        })?;

        Ok(Self {
            output,
            tree: State::new(superblock, hasher)?,
            output_range: None,
            phase: Phase::Open,
        })
    }

    /// Returns the root digest after the tree is complete and flushed.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] if more input is needed,
    /// [`io::ErrorKind::WouldBlock`] if the tree needs to be flushed, or
    /// [`io::ErrorKind::Other`] after an output error.
    pub fn digest(&self) -> io::Result<&[u8]> {
        match &self.phase {
            Phase::Open => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "verity input has not reached its final data block",
            )),
            Phase::Sealed => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "verity tree must be flushed before its digest is available",
            )),
            #[cfg(feature = "futures-io")]
            Phase::Draining(draining) => match draining.after {
                AfterDrain::Finish => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "verity tree must be flushed before its digest is available",
                )),
                AfterDrain::AcceptInput | AfterDrain::FlushIntermediate => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "verity input has not reached its final data block",
                )),
            },
            #[cfg(feature = "futures-io")]
            Phase::SeekingEnd { .. } | Phase::FlushingOutput(AfterFlush::Complete(_)) => {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "verity tree must be flushed before its digest is available",
                ))
            }
            #[cfg(feature = "futures-io")]
            Phase::FlushingOutput(AfterFlush::Open) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "verity input has not reached its final data block",
            )),
            Phase::Complete(digest) => Ok(digest),
            Phase::Failed => Err(io::Error::other(
                "cannot use a tree writer after an output failure",
            )),
        }
    }

    fn ensure_writable(&self) -> io::Result<()> {
        match self.phase {
            Phase::Open => Ok(()),
            Phase::Failed => Err(io::Error::other(
                "cannot use a tree writer after an output failure",
            )),
            #[cfg(feature = "futures-io")]
            Phase::Draining(_) | Phase::SeekingEnd { .. } | Phase::FlushingOutput(_) => {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "an asynchronous tree-writer operation is still in progress",
                ))
            }
            Phase::Sealed | Phase::Complete(_) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "verity input is already complete",
            )),
        }
    }

    fn seal_if_complete(&mut self) {
        if self.tree.reached_end() {
            self.phase = Phase::Sealed;
        }
    }
}

struct OutputRange {
    start: u64,
    end: u64,
}

enum Phase {
    Open,
    Sealed,
    #[cfg(feature = "futures-io")]
    Draining(Draining),
    #[cfg(feature = "futures-io")]
    SeekingEnd {
        digest: Box<[u8]>,
    },
    #[cfg(feature = "futures-io")]
    FlushingOutput(AfterFlush),
    Complete(Box<[u8]>),
    Failed,
}

#[derive(Clone, Copy)]
enum Drain {
    Full,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FlushMode {
    Intermediate,
    Final,
}

impl FlushMode {
    const fn drain(self) -> Drain {
        match self {
            Self::Intermediate => Drain::Full,
            Self::Final => Drain::All,
        }
    }
}

enum Failure {
    Recoverable(io::Error),
    Fatal(io::Error),
}

impl Failure {
    fn into_error(self) -> io::Error {
        match self {
            Self::Recoverable(error) | Self::Fatal(error) => error,
        }
    }
}

#[cfg(feature = "futures-io")]
struct Draining {
    mode: Drain,
    after: AfterDrain,
    step: DrainStep,
}

#[cfg(feature = "futures-io")]
#[derive(Clone, Copy)]
enum AfterDrain {
    AcceptInput,
    FlushIntermediate,
    Finish,
}

#[cfg(feature = "futures-io")]
enum DrainStep {
    Next,
    Writing(BlockWrite),
}

#[cfg(feature = "futures-io")]
enum BlockWrite {
    Seeking(PendingBlock),
    Writing { block: PendingBlock, written: usize },
}

#[cfg(feature = "futures-io")]
enum AfterFlush {
    Open,
    Complete(Box<[u8]>),
}

#[cfg(feature = "futures-io")]
enum Progress {
    Continue,
    Input,
    Flush,
}
