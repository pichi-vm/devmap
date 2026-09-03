// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::io::{self, SeekFrom};
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_verity::{TreeWriter, Verified};
use futures::executor::block_on;
use futures::io::{AsyncSeek, AsyncWrite, AsyncWriteExt, Cursor};

#[derive(Debug, Default)]
struct PendingOutput {
    cursor: std::io::Cursor<Vec<u8>>,
    seek_ready: bool,
    write_ready: bool,
    flush_ready: bool,
}

impl PendingOutput {
    fn pend(ready: &mut bool, cx: &Context<'_>) -> bool {
        if *ready {
            *ready = false;
            false
        } else {
            *ready = true;
            cx.waker().wake_by_ref();
            true
        }
    }
}

impl AsyncSeek for PendingOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        if Self::pend(&mut self.seek_ready, cx) {
            return Poll::Pending;
        }
        Poll::Ready(std::io::Seek::seek(&mut self.cursor, position))
    }
}

impl AsyncWrite for PendingOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if Self::pend(&mut self.write_ready, cx) {
            return Poll::Pending;
        }
        let count = bytes.len().min(7);
        Poll::Ready(std::io::Write::write(&mut self.cursor, &bytes[..count]))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if Self::pend(&mut self.flush_ready, cx) {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[derive(Debug, Default)]
struct FailingOutput {
    cursor: std::io::Cursor<Vec<u8>>,
}

impl AsyncSeek for FailingOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Poll::Ready(std::io::Seek::seek(&mut self.cursor, position))
    }
}

impl AsyncWrite for FailingOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected output failure",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Default)]
struct FailingSeekOutput;

impl AsyncSeek for FailingSeekOutput {
    fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected seek failure",
        )))
    }
}

impl AsyncWrite for FailingSeekOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Default)]
struct FailingLaterSeekOutput {
    cursor: Cursor<Vec<u8>>,
    seeks: usize,
}

impl AsyncSeek for FailingLaterSeekOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        self.seeks += 1;
        if self.seeks == 2 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected later seek failure",
            )));
        }
        Pin::new(&mut self.cursor).poll_seek(cx, position)
    }
}

impl AsyncWrite for FailingLaterSeekOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.cursor).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.cursor).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.cursor).poll_close(cx)
    }
}

#[derive(Debug, Default)]
struct FailingFlushOutput {
    cursor: Cursor<Vec<u8>>,
}

impl AsyncSeek for FailingFlushOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.cursor).poll_seek(cx, position)
    }
}

impl AsyncWrite for FailingFlushOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.cursor).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected flush failure",
        )))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Default)]
struct ZeroWritingOutput {
    cursor: Cursor<Vec<u8>>,
}

impl AsyncSeek for ZeroWritingOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.cursor).poll_seek(cx, position)
    }
}

impl AsyncWrite for ZeroWritingOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Default)]
struct OverreportingOutput {
    cursor: Cursor<Vec<u8>>,
}

impl AsyncSeek for OverreportingOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.cursor).poll_seek(cx, position)
    }
}

impl AsyncWrite for OverreportingOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len() + 1))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Default)]
struct FailingCloseOutput {
    cursor: Cursor<Vec<u8>>,
}

impl AsyncSeek for FailingCloseOutput {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.cursor).poll_seek(cx, position)
    }
}

impl AsyncWrite for FailingCloseOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.cursor).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected close failure",
        )))
    }
}

fn superblock(data_blocks: u64) -> Verified {
    Verified::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(data_blocks).unwrap())
        .unwrap()
}

#[test]
fn asynchronous_output_matches_synchronous_output() {
    let superblock = superblock(17);
    let data: Vec<_> = (0..16 * 512 + 7).map(|index| index as u8).collect();

    let mut synchronous = std::io::Cursor::new(Vec::new());
    let synchronous_digest = {
        let mut tree = TreeWriter::new(&mut synchronous, superblock.clone()).unwrap();
        std::io::Write::write_all(&mut tree, &data).unwrap();
        std::io::Write::flush(&mut tree).unwrap();
        tree.digest().unwrap().to_vec()
    };

    let mut asynchronous = Cursor::new(Vec::new());
    let asynchronous_digest = block_on(async {
        let mut tree = TreeWriter::new(&mut asynchronous, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &data).await.unwrap();
        assert_eq!(
            tree.digest().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        tree.digest().unwrap().to_vec()
    });

    assert_eq!(asynchronous.into_inner(), synchronous.into_inner());
    assert_eq!(asynchronous_digest, synchronous_digest);
}

#[test]
fn asynchronous_flush_obeys_data_block_boundaries() {
    block_on(async {
        let superblock = superblock(3);
        let mut output = Cursor::new(Vec::new());
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();

        AsyncWriteExt::write_all(&mut tree, &[1; 511])
            .await
            .unwrap();
        assert_eq!(
            AsyncWriteExt::flush(&mut tree).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        AsyncWriteExt::write_all(&mut tree, &[1]).await.unwrap();
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(
            tree.digest().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        AsyncWriteExt::write_all(&mut tree, &[2; 513])
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[3])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    });
}

#[test]
fn asynchronous_close_rejects_incomplete_input() {
    block_on(async {
        let superblock = superblock(3);
        let mut output = Cursor::new(Vec::new());
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0; 512])
            .await
            .unwrap();

        assert_eq!(
            AsyncWriteExt::close(&mut tree).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    });
}

#[test]
fn asynchronous_close_completes_final_input() {
    block_on(async {
        let superblock = superblock(1);
        let mut output = Cursor::new(Vec::new());
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0xa5]).await.unwrap();
        AsyncWriteExt::close(&mut tree).await.unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
    });
}

#[test]
fn a_cancelled_flush_can_be_resumed() {
    block_on(async {
        let superblock = superblock(17);
        let mut output = PendingOutput::default();
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0xa5; 16 * 512 + 1])
            .await
            .unwrap();

        let mut flush = Box::pin(AsyncWriteExt::flush(&mut tree));
        assert!(futures::poll!(flush.as_mut()).is_pending());
        drop(flush);

        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
    });
}

#[test]
fn a_cancelled_write_can_be_completed_by_flush() {
    block_on(async {
        let superblock = superblock(17);
        let mut output = PendingOutput::default();
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0xa5; 16 * 512])
            .await
            .unwrap();

        let final_block = [0x5a; 512];
        let mut write = Box::pin(AsyncWriteExt::write_all(&mut tree, &final_block));
        assert!(futures::poll!(write.as_mut()).is_pending());
        drop(write);

        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(
            tree.digest().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        AsyncWriteExt::write_all(&mut tree, &final_block)
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
    });
}

#[test]
fn a_cancelled_intermediate_flush_can_be_completed_by_write() {
    block_on(async {
        let superblock = superblock(3);
        let mut output = PendingOutput::default();
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0xa5; 512])
            .await
            .unwrap();

        let mut flush = Box::pin(AsyncWriteExt::flush(&mut tree));
        assert!(futures::poll!(flush.as_mut()).is_pending());
        drop(flush);

        AsyncWriteExt::write_all(&mut tree, &[0x5a; 2 * 512])
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
    });
}

#[test]
fn asynchronous_operations_resume_after_pending_and_short_writes() {
    let superblock = superblock(300);
    let data: Vec<_> = (0..300 * 512).map(|index| index as u8).collect();

    let mut expected = std::io::Cursor::new(Vec::new());
    let expected_digest = {
        let mut tree = TreeWriter::new(&mut expected, superblock.clone()).unwrap();
        std::io::Write::write_all(&mut tree, &data).unwrap();
        std::io::Write::flush(&mut tree).unwrap();
        tree.digest().unwrap().to_vec()
    };

    let mut output = PendingOutput::default();
    let digest = block_on(async {
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        AsyncWriteExt::write_all(&mut tree, &data).await.unwrap();
        AsyncWriteExt::flush(&mut tree).await.unwrap();
        tree.digest().unwrap().to_vec()
    });

    assert_eq!(output.cursor.into_inner(), expected.into_inner());
    assert_eq!(digest, expected_digest);
}

#[test]
fn an_asynchronous_output_failure_poisons_the_writer() {
    block_on(async {
        let superblock = superblock(17);
        let mut tree = TreeWriter::new(FailingOutput::default(), superblock).unwrap();

        for _ in 0..16 {
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap();
        }
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_seek_failure_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(FailingSeekOutput, superblock(1)).unwrap();
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
    });
}

#[test]
fn an_asynchronous_hash_block_seek_failure_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(FailingLaterSeekOutput::default(), superblock(17)).unwrap();
        for _ in 0..16 {
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap();
        }
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_final_seek_failure_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(FailingLaterSeekOutput::default(), superblock(1)).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0; 512])
            .await
            .unwrap();
        assert_eq!(
            AsyncWriteExt::flush(&mut tree).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_flush_failure_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(FailingFlushOutput::default(), superblock(1)).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0; 512])
            .await
            .unwrap();
        assert_eq!(
            AsyncWriteExt::flush(&mut tree).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_zero_write_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(ZeroWritingOutput::default(), superblock(17)).unwrap();
        for _ in 0..16 {
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap();
        }
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_overreported_write_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(OverreportingOutput::default(), superblock(17)).unwrap();
        for _ in 0..16 {
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap();
        }
        assert_eq!(
            AsyncWriteExt::write_all(&mut tree, &[0; 512])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}

#[test]
fn an_asynchronous_close_failure_poisons_the_writer() {
    block_on(async {
        let mut tree = TreeWriter::new(FailingCloseOutput::default(), superblock(1)).unwrap();
        AsyncWriteExt::write_all(&mut tree, &[0; 512])
            .await
            .unwrap();
        assert_eq!(
            AsyncWriteExt::close(&mut tree).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
    });
}
