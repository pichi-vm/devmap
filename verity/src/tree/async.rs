// SPDX-License-Identifier: Apache-2.0

use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncSeek, AsyncWrite};

use super::{
    AfterDrain, AfterFlush, BlockWrite, Drain, DrainStep, Draining, Failure, FlushMode,
    OutputRange, Phase, Progress, TreeWriter,
};

impl<W: AsyncWrite + AsyncSeek + Unpin> TreeWriter<W> {
    fn poll_initialize(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        if self.output_range.is_some() {
            return Poll::Ready(Ok(()));
        }
        if !self.initializing {
            if let Err(error) = Pin::new(&mut self.output).start_seek(SeekFrom::Current(0)) {
                return Poll::Ready(Err(Failure::Fatal(error)));
            }
            self.initializing = true;
        }
        let start = match Pin::new(&mut self.output).poll_complete(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Failure::Fatal(error))),
            Poll::Ready(Ok(start)) => start,
        };
        self.initializing = false;
        let Some(end) = start.checked_add(self.tree.tree_size()) else {
            return Poll::Ready(Err(Failure::Fatal(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hash tree does not fit after the output's current position",
            ))));
        };
        self.output_range = Some(OutputRange { start, end });
        Poll::Ready(Ok(()))
    }

    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        loop {
            let phase = std::mem::replace(&mut self.phase, Phase::Failed);
            let progress = match phase {
                Phase::Draining(draining) => self.poll_draining(cx, draining),
                Phase::SeekingEnd { digest, started } => self.poll_seek_end(cx, digest, started),
                Phase::FlushingOutput(after) => self.poll_output_flush(cx, after),
                phase => {
                    self.phase = phase;
                    return Poll::Ready(Ok(Progress::Input));
                }
            };
            match progress {
                Poll::Ready(Ok(Progress::Continue)) => {}
                progress => return progress,
            }
        }
    }

    fn poll_draining(
        &mut self,
        cx: &mut Context<'_>,
        mut draining: Draining,
    ) -> Poll<Result<Progress, Failure>> {
        match std::mem::replace(&mut draining.step, DrainStep::Next) {
            DrainStep::Next => {
                if let Some(block) = self.tree.take_pending(draining.mode) {
                    draining.step = DrainStep::Writing(BlockWrite::Starting(block));
                    self.phase = Phase::Draining(draining);
                    return Poll::Ready(Ok(Progress::Continue));
                }

                match draining.after {
                    AfterDrain::AcceptInput => {
                        self.phase = Phase::Open;
                        Poll::Ready(Ok(Progress::Input))
                    }
                    AfterDrain::FlushIntermediate => {
                        self.phase = Phase::FlushingOutput(AfterFlush::Open);
                        Poll::Ready(Ok(Progress::Continue))
                    }
                    AfterDrain::Finish => {
                        let Some(digest) = self.tree.take_digest() else {
                            return Poll::Ready(Err(Failure::Fatal(io::Error::other(
                                "complete verity input did not produce a root digest",
                            ))));
                        };
                        self.phase = Phase::SeekingEnd {
                            digest,
                            started: false,
                        };
                        Poll::Ready(Ok(Progress::Continue))
                    }
                }
            }
            DrainStep::Writing(write) => self.poll_block_write(cx, draining, write),
        }
    }

    fn poll_block_write(
        &mut self,
        cx: &mut Context<'_>,
        mut draining: Draining,
        write: BlockWrite,
    ) -> Poll<Result<Progress, Failure>> {
        match write {
            BlockWrite::Starting(block) => {
                let Some(range) = &self.output_range else {
                    return Poll::Ready(Err(Failure::Fatal(io::Error::other(
                        "hash tree output is not initialized",
                    ))));
                };
                let Some(offset) = range.start.checked_add(block.offset()) else {
                    return Poll::Ready(Err(Failure::Fatal(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "hash tree output offset overflows",
                    ))));
                };
                if let Err(error) = Pin::new(&mut self.output).start_seek(SeekFrom::Start(offset)) {
                    return Poll::Ready(Err(Failure::Fatal(error)));
                }
                draining.step = DrainStep::Writing(BlockWrite::Seeking(block));
                self.phase = Phase::Draining(draining);
                Poll::Ready(Ok(Progress::Continue))
            }
            BlockWrite::Seeking(block) => match Pin::new(&mut self.output).poll_complete(cx) {
                Poll::Pending => {
                    draining.step = DrainStep::Writing(BlockWrite::Seeking(block));
                    self.phase = Phase::Draining(draining);
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::Fatal(error))),
                Poll::Ready(Ok(_)) => {
                    draining.step = DrainStep::Writing(BlockWrite::Writing { block, written: 0 });
                    self.phase = Phase::Draining(draining);
                    Poll::Ready(Ok(Progress::Continue))
                }
            },
            BlockWrite::Writing { block, written } => {
                match Pin::new(&mut self.output).poll_write(cx, &block.bytes()[written..]) {
                    Poll::Pending => {
                        draining.step = DrainStep::Writing(BlockWrite::Writing { block, written });
                        self.phase = Phase::Draining(draining);
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::Fatal(error))),
                    Poll::Ready(Ok(0)) => {
                        Poll::Ready(Err(Failure::Fatal(io::ErrorKind::WriteZero.into())))
                    }
                    Poll::Ready(Ok(count)) => {
                        let Some(written) = written.checked_add(count) else {
                            return Poll::Ready(Err(Failure::Fatal(io::Error::other(
                                "asynchronous output write count overflows",
                            ))));
                        };
                        if written > block.bytes().len() {
                            return Poll::Ready(Err(Failure::Fatal(io::Error::other(
                                "asynchronous output wrote more bytes than requested",
                            ))));
                        }
                        if written < block.bytes().len() {
                            draining.step =
                                DrainStep::Writing(BlockWrite::Writing { block, written });
                            self.phase = Phase::Draining(draining);
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }

                        if let Err(error) = self.tree.commit(block) {
                            return Poll::Ready(Err(Failure::Fatal(error)));
                        }
                        draining.step = DrainStep::Next;
                        self.phase = Phase::Draining(draining);
                        Poll::Ready(Ok(Progress::Continue))
                    }
                }
            }
        }
    }

    fn poll_seek_end(
        &mut self,
        cx: &mut Context<'_>,
        digest: Box<[u8]>,
        started: bool,
    ) -> Poll<Result<Progress, Failure>> {
        let Some(range) = &self.output_range else {
            return Poll::Ready(Err(Failure::Fatal(io::Error::other(
                "hash tree output is not initialized",
            ))));
        };
        if !started {
            if let Err(error) = Pin::new(&mut self.output).start_seek(SeekFrom::Start(range.end)) {
                return Poll::Ready(Err(Failure::Fatal(error)));
            }
            self.phase = Phase::SeekingEnd {
                digest,
                started: true,
            };
            return Poll::Ready(Ok(Progress::Continue));
        }
        match Pin::new(&mut self.output).poll_complete(cx) {
            Poll::Pending => {
                self.phase = Phase::SeekingEnd {
                    digest,
                    started: true,
                };
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::Fatal(error))),
            Poll::Ready(Ok(_)) => {
                self.phase = Phase::FlushingOutput(AfterFlush::Complete(digest));
                Poll::Ready(Ok(Progress::Continue))
            }
        }
    }

    fn poll_output_flush(
        &mut self,
        cx: &mut Context<'_>,
        after: AfterFlush,
    ) -> Poll<Result<Progress, Failure>> {
        match Pin::new(&mut self.output).poll_flush(cx) {
            Poll::Pending => {
                self.phase = Phase::FlushingOutput(after);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(Failure::Fatal(error))),
            Poll::Ready(Ok(())) => {
                self.phase = match after {
                    AfterFlush::Open => Phase::Open,
                    AfterFlush::Complete(digest) => Phase::Complete(digest),
                };
                Poll::Ready(Ok(Progress::Flush))
            }
        }
    }

    fn poll_busy(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Progress>> {
        match self.poll_progress(cx) {
            Poll::Ready(Err(Failure::Fatal(error))) => {
                self.phase = Phase::Failed;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(Failure::Recoverable(error))) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(progress)) => Poll::Ready(Ok(progress)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_busy(&self) -> bool {
        matches!(
            self.phase,
            Phase::Draining(_) | Phase::SeekingEnd { .. } | Phase::FlushingOutput(_)
        )
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
impl<W: AsyncWrite + AsyncSeek + Unpin> AsyncWrite for TreeWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.is_busy() {
            match this.poll_busy(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        if let Err(error) = this.ensure_writable() {
            return Poll::Ready(Err(error));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match this.poll_initialize(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(failure)) => {
                this.phase = Phase::Failed;
                return Poll::Ready(Err(failure.into_error()));
            }
            Poll::Ready(Ok(())) => {}
        }
        this.phase = Phase::Draining(Draining {
            mode: Drain::Full,
            after: AfterDrain::AcceptInput,
            step: DrainStep::Next,
        });
        match this.poll_busy(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => {}
        }

        let copied = match this.tree.accept(input) {
            Ok(copied) => copied,
            Err(Failure::Recoverable(error)) => return Poll::Ready(Err(error)),
            Err(Failure::Fatal(error)) => {
                this.phase = Phase::Failed;
                return Poll::Ready(Err(error));
            }
        };
        this.seal_if_complete();
        Poll::Ready(Ok(copied))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.phase, Phase::Failed) {
            return Poll::Ready(Err(io::Error::other(
                "cannot use a tree writer after an output failure",
            )));
        }
        if matches!(this.phase, Phase::Complete(_)) {
            return match Pin::new(&mut this.output).poll_flush(cx) {
                Poll::Ready(Err(error)) => {
                    this.phase = Phase::Failed;
                    Poll::Ready(Err(error))
                }
                result => result,
            };
        }

        if this.is_busy() {
            match this.poll_busy(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(Progress::Flush)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Progress::Input | Progress::Continue)) => {}
            }
        }

        match this.poll_initialize(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(failure)) => {
                this.phase = Phase::Failed;
                return Poll::Ready(Err(failure.into_error()));
            }
            Poll::Ready(Ok(())) => {}
        }
        let mode = this.tree.begin_flush();
        this.phase = Phase::Draining(Draining {
            mode: mode.drain(),
            after: match mode {
                FlushMode::Intermediate => AfterDrain::FlushIntermediate,
                FlushMode::Final => AfterDrain::Finish,
            },
            step: DrainStep::Next,
        });

        match this.poll_busy(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let this = self.as_mut().get_mut();
            if matches!(this.phase, Phase::Failed) {
                return Poll::Ready(Err(io::Error::other(
                    "cannot use a tree writer after an output failure",
                )));
            }
            if this.is_busy() {
                match this.poll_busy(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(_)) => {}
                }
            }
            if matches!(this.phase, Phase::Open) && !this.tree.reached_end() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "verity input has not reached its final data block",
                )));
            }
        }

        match AsyncWrite::poll_flush(self.as_mut(), cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let this = self.get_mut();
        match Pin::new(&mut this.output).poll_shutdown(cx) {
            Poll::Ready(Err(error)) => {
                this.phase = Phase::Failed;
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}
