// SPDX-License-Identifier: Apache-2.0

use super::{Hashes, State};
use crate::layout::Layout;
use devmap_core::traits::tokio::Geometry;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Idle,
    Start { level: usize },
    Seeking { level: usize },
    Reading { level: usize, filled: usize },
}

impl<H: Geometry> Hashes<H> {
    pub(crate) async fn validate_storage_async(&mut self) -> io::Result<()> {
        let block_size = self.inner.block_size()?;
        let count = self.inner.count().await?;
        self.validate_geometry(block_size, count)
    }
}

impl<H: AsyncRead + AsyncSeek + Unpin> Hashes<H> {
    pub(crate) fn poll_lookup(
        &mut self,
        cx: &mut Context<'_>,
        index: u64,
        root: &[u8],
    ) -> Poll<io::Result<&[u8]>> {
        if self.authentication.is_none() {
            self.authentication = Some(State::new(&self.layout)?);
        }
        let state = self
            .authentication
            .as_mut()
            .ok_or_else(|| io::Error::other("missing verifier"))?;
        match state.poll_lookup(cx, &mut self.inner, &self.layout, index, root) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.phase = Phase::Idle;
                Poll::Ready(result.map(|()| state.expected.as_ref()))
            }
        }
    }
}

impl State {
    fn poll_lookup<H: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        storage: &mut H,
        layout: &Layout,
        index: u64,
        root: &[u8],
    ) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                Phase::Idle => {
                    self.begin(layout, index, root)?;
                    let Some(level) = layout.level_offsets.len().checked_sub(1) else {
                        return Poll::Ready(Ok(()));
                    };
                    self.phase = Phase::Start { level };
                }
                Phase::Start { level } => {
                    ready!(Pin::new(&mut *storage).poll_complete(cx))?;
                    Pin::new(&mut *storage)
                        .start_seek(io::SeekFrom::Start(Self::offset(layout, level, index)))?;
                    self.phase = Phase::Seeking { level };
                }
                Phase::Seeking { level } => {
                    ready!(Pin::new(&mut *storage).poll_complete(cx))?;
                    self.phase = Phase::Reading { level, filled: 0 };
                }
                Phase::Reading { level, filled } => {
                    let mut output = ReadBuf::new(&mut self.block[filled..]);
                    match ready!(Pin::new(&mut *storage).poll_read(cx, &mut output)) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    }
                    let count = output.filled().len();
                    if count == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let filled = filled + count;
                    if filled == self.block.len() {
                        self.advance(layout, level, index)?;
                        if level == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        self.phase = Phase::Start { level: level - 1 };
                    } else {
                        self.phase = Phase::Reading { level, filled };
                    }
                }
            }
        }
    }
}
