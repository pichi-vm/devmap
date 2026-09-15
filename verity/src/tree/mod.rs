// SPDX-License-Identifier: Apache-2.0

use std::io;

#[cfg(feature = "tokio")]
use state::PendingBlock;
use state::State;

use crate::Parameters;

#[cfg(feature = "tokio")]
mod r#async;
mod state;
mod sync;

/// Writes a dm-verity hash tree to a seekable output.
///
/// Write exactly the number of complete data blocks declared by the
/// parameters. Input slices may have any length; only fragments are copied
/// into the internal block buffer. Complete aligned blocks are hashed directly.
///
/// `flush` has its conventional meaning: it drains available hash output but
/// neither pads nor seals incomplete input. Call [`finish`](Self::finish)
/// after the exact input length has been written and flushed. Dropping the writer
/// does not flush it. The writer cannot be used after an output error.
#[allow(missing_debug_implementations)]
#[must_use = "dropping a tree writer does not finish the hash tree"]
pub(crate) struct TreeWriter<W> {
    output: W,
    tree: State,
    output_range: Option<OutputRange>,
    phase: Phase,
    #[cfg(feature = "tokio")]
    initializing: bool,
}

impl<W> TreeWriter<W> {
    /// Creates a tree writer at the output's current position.
    ///
    /// This writes only the hash tree. Write the encoded
    /// header and its block padding first. Creating the
    /// writer performs no I/O.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] if the feature for the selected
    /// hash algorithm is not enabled.
    pub(crate) fn new(output: W, parameters: Parameters) -> io::Result<Self> {
        let hasher = parameters.algorithm().hasher().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "hash algorithm support is not enabled",
            )
        })?;

        Ok(Self {
            output,
            tree: State::new(parameters, hasher),
            output_range: None,
            phase: Phase::Open,
            #[cfg(feature = "tokio")]
            initializing: false,
        })
    }

    pub(crate) const fn output_mut(&mut self) -> &mut W {
        &mut self.output
    }

    /// Returns the output, parameters, and root only after a successful final flush.
    pub(crate) fn finish(self) -> io::Result<(W, Parameters, Box<[u8]>)> {
        match self.phase {
            Phase::Complete(digest) => Ok((self.output, self.tree.parameters, digest)),
            Phase::Open => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "verity input has not reached its final data block",
            )),
            Phase::Failed => Err(io::Error::other(
                "cannot use a tree writer after an output failure",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "verity tree must be flushed before its digest is available",
            )),
        }
    }

    fn ensure_writable(&self) -> io::Result<()> {
        match self.phase {
            Phase::Open => Ok(()),
            Phase::Failed => Err(io::Error::other(
                "cannot use a tree writer after an output failure",
            )),
            #[cfg(feature = "tokio")]
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
    #[cfg(feature = "tokio")]
    Draining(Draining),
    #[cfg(feature = "tokio")]
    SeekingEnd {
        digest: Box<[u8]>,
        started: bool,
    },
    #[cfg(feature = "tokio")]
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

#[cfg(feature = "tokio")]
struct Draining {
    mode: Drain,
    after: AfterDrain,
    step: DrainStep,
}

#[cfg(feature = "tokio")]
#[derive(Clone, Copy)]
enum AfterDrain {
    AcceptInput,
    FlushIntermediate,
    Finish,
}

#[cfg(feature = "tokio")]
enum DrainStep {
    Next,
    Writing(BlockWrite),
}

#[cfg(feature = "tokio")]
enum BlockWrite {
    Starting(PendingBlock),
    Seeking(PendingBlock),
    Writing { block: PendingBlock, written: usize },
}

#[cfg(feature = "tokio")]
enum AfterFlush {
    Open,
    Complete(Box<[u8]>),
}

#[cfg(feature = "tokio")]
enum Progress {
    Continue,
    Input,
    Flush,
}
