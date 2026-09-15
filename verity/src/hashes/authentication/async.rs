// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use devmap_core::traits::tokio::Geometry;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use super::{Hashes, State};

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Idle,
    Start {
        level: usize,
        child: u64,
    },
    Seeking {
        level: usize,
        child: u64,
    },
    Reading {
        level: usize,
        child: u64,
        filled: usize,
    },
}

impl<H: Geometry> Hashes<H> {
    pub(crate) async fn validate_storage_async(&mut self) -> io::Result<()> {
        let block_size = self.inner.block_size()?;
        let count = self.inner.count().await?;
        self.validate_geometry(block_size, count)
    }
}

impl<H: AsyncRead + AsyncSeek + Unpin> Hashes<H> {
    pub(crate) fn poll_authenticate(
        &mut self,
        cx: &mut Context<'_>,
        index: u64,
        data: &[u8],
        root: &[u8],
    ) -> Poll<io::Result<()>> {
        if self.authentication.is_none() {
            self.authentication = Some(State::new(&self.header)?);
        }
        let state = self
            .authentication
            .as_mut()
            .ok_or_else(|| io::Error::other("missing verifier"))?;
        let result = state.poll_authenticate(cx, &mut self.inner, &self.header, index, data, root);
        if result.is_ready() {
            state.phase = Phase::Idle;
        }
        result
    }
}

impl State {
    fn poll_authenticate<H: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        storage: &mut H,
        header: &crate::Header,
        index: u64,
        data: &[u8],
        root: &[u8],
    ) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                Phase::Idle => {
                    self.begin(header, index, data)?;
                    self.phase = Phase::Start {
                        level: 0,
                        child: index,
                    };
                }
                Phase::Start { level, child } => {
                    if level == header.layout.level_offsets.len() {
                        return Poll::Ready(self.check_root(root));
                    }
                    ready!(Pin::new(&mut *storage).poll_complete(cx))?;
                    Pin::new(&mut *storage)
                        .start_seek(io::SeekFrom::Start(Self::offset(header, level, child)))?;
                    self.phase = Phase::Seeking { level, child };
                }
                Phase::Seeking { level, child } => {
                    ready!(Pin::new(&mut *storage).poll_complete(cx))?;
                    self.phase = Phase::Reading {
                        level,
                        child,
                        filled: 0,
                    };
                }
                Phase::Reading {
                    level,
                    child,
                    filled,
                } => {
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
                        self.advance(header, child)?;
                        self.phase = Phase::Start {
                            level: level + 1,
                            child: child / header.layout.hashes_per_block as u64,
                        };
                    } else {
                        self.phase = Phase::Reading {
                            level,
                            child,
                            filled,
                        };
                    }
                }
            }
        }
    }
}
