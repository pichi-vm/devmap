// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::io::{self, Seek as _, SeekFrom};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_verity::{TreeWriter, Verified};
use tokio::io::{AsyncSeek, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Default)]
struct Output {
    cursor: std::io::Cursor<Vec<u8>>,
    seek: Option<SeekFrom>,
    ready: bool,
    fail: bool,
}

impl Output {
    fn pause(&mut self, cx: &Context<'_>) -> bool {
        self.ready = !self.ready;
        if self.ready {
            cx.waker().wake_by_ref();
        }
        self.ready
    }
}

impl AsyncSeek for Output {
    fn start_seek(mut self: Pin<&mut Self>, seek: SeekFrom) -> io::Result<()> {
        if self.seek.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.seek = Some(seek);
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        if self.pause(cx) {
            return Poll::Pending;
        }
        let result = match self.seek.take() {
            Some(seek) => self.cursor.seek(seek),
            None => Ok(self.cursor.position()),
        };
        Poll::Ready(result)
    }
}

impl AsyncWrite for Output {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pause(cx) {
            return Poll::Pending;
        }
        if self.fail {
            return Poll::Ready(Err(io::Error::other("injected output failure")));
        }
        let count = bytes.len().min(7);
        Poll::Ready(std::io::Write::write(&mut self.cursor, &bytes[..count]))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pause(cx) {
            return Poll::Pending;
        }
        if self.fail {
            Poll::Ready(Err(io::Error::other("injected output failure")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn superblock(blocks: u64) -> Verified {
    Verified::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(blocks).unwrap())
        .unwrap()
}

#[tokio::test]
async fn asynchronous_output_matches_synchronous_output() {
    let superblock = superblock(17);
    let data: Vec<_> = (0..17 * 512).map(|index| index as u8).collect();
    let mut synchronous = std::io::Cursor::new(Vec::new());
    synchronous.set_position(123);
    let expected = {
        let mut tree = TreeWriter::new(&mut synchronous, superblock.clone()).unwrap();
        std::io::Write::write_all(&mut tree, &data).unwrap();
        std::io::Write::flush(&mut tree).unwrap();
        tree.digest().unwrap().to_vec()
    };
    let mut output = Output::default();
    output.cursor.set_position(123);
    let actual = {
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        tree.write_all(&data).await.unwrap();
        tree.flush().await.unwrap();
        tree.digest().unwrap().to_vec()
    };
    assert_eq!(actual, expected);
    assert_eq!(output.cursor.into_inner(), synchronous.into_inner());
}

#[tokio::test]
async fn arbitrary_fragments_are_accepted() {
    let mut output = Output::default();
    let mut tree = TreeWriter::new(&mut output, superblock(3)).unwrap();
    let data = vec![0x5a; 3 * 512];
    for fragment in data.chunks(73) {
        tree.write_all(fragment).await.unwrap();
    }
    tree.flush().await.unwrap();
    assert_eq!(tree.digest().unwrap().len(), 32);
}

#[tokio::test]
async fn flush_does_not_pad_or_seal_partial_input() {
    let mut output = Output::default();
    let mut tree = TreeWriter::new(&mut output, superblock(2)).unwrap();
    tree.write_all(&vec![1; 513]).await.unwrap();
    tree.flush().await.unwrap();
    assert_eq!(
        tree.digest().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    tree.write_all(&vec![0; 511]).await.unwrap();
    tree.flush().await.unwrap();
    assert_eq!(tree.digest().unwrap().len(), 32);
}

#[tokio::test]
async fn shutdown_rejects_incomplete_input() {
    let mut output = Output::default();
    let mut tree = TreeWriter::new(&mut output, superblock(2)).unwrap();
    tree.write_all(&vec![0; 512]).await.unwrap();
    assert_eq!(
        tree.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn output_failure_poisons_the_writer() {
    let mut output = Output {
        fail: true,
        ..Output::default()
    };
    let mut tree = TreeWriter::new(&mut output, superblock(2)).unwrap();
    tree.write_all(&vec![0; 1024]).await.unwrap();
    assert!(tree.flush().await.is_err());
    assert!(tree.flush().await.is_err());
}
