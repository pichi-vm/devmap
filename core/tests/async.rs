// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "futures-io")]

use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_core::{BlockIo, ByteCursor, Region, Zero};
use futures::executor::block_on;
use futures::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, Cursor,
};

#[derive(Debug)]
struct PendingIo {
    inner: std::io::Cursor<Vec<u8>>,
    pending: bool,
}

impl PendingIo {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: std::io::Cursor::new(bytes),
            pending: true,
        }
    }

    fn poll_pending(&mut self, cx: &Context<'_>) -> bool {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            true
        } else {
            self.pending = true;
            false
        }
    }
}

impl AsyncRead for PendingIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.poll_pending(cx) {
            return Poll::Pending;
        }
        let count = output.len().min(2);
        Poll::Ready(std::io::Read::read(&mut self.inner, &mut output[..count]))
    }
}

impl AsyncWrite for PendingIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.poll_pending(cx) {
            return Poll::Pending;
        }
        let count = input.len().min(2);
        Poll::Ready(std::io::Write::write(&mut self.inner, &input[..count]))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.poll_pending(cx) {
            return Poll::Pending;
        }
        Poll::Ready(std::io::Write::flush(&mut self.inner))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncSeek for PendingIo {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        position: std::io::SeekFrom,
    ) -> Poll<std::io::Result<u64>> {
        if self.poll_pending(cx) {
            return Poll::Pending;
        }
        Poll::Ready(std::io::Seek::seek(&mut self.inner, position))
    }
}

#[test]
fn zero_has_the_same_async_byte_interface() {
    block_on(async {
        let blocks = Region::<_, 4>::new(Zero, 0, 2).unwrap();
        let mut bytes = ByteCursor::new(blocks).unwrap();

        bytes.write_all(&[1, 2, 3, 4, 5]).await.unwrap();
        bytes.flush().await.unwrap();
        bytes.seek(std::io::SeekFrom::Start(0)).await.unwrap();

        let mut output = [0xff; 8];
        bytes.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [0; 8]);
    });
}

#[test]
fn block_io_and_byte_cursor_work_asynchronously() {
    block_on(async {
        let mut storage = Cursor::new((0..12).collect::<Vec<_>>());
        {
            let blocks = BlockIo::<_, 4>::new(&mut storage, 3).unwrap();
            let mut bytes = ByteCursor::new(blocks).unwrap();

            bytes.seek(std::io::SeekFrom::Start(3)).await.unwrap();
            bytes.write_all(&[20, 21, 22, 23, 24, 25]).await.unwrap();
            bytes.flush().await.unwrap();
            bytes.seek(std::io::SeekFrom::Start(2)).await.unwrap();

            let mut output = [0; 8];
            bytes.read_exact(&mut output).await.unwrap();
            assert_eq!(output, [2, 20, 21, 22, 23, 24, 25, 9]);
        }
        assert_eq!(
            storage.into_inner(),
            [0, 1, 2, 20, 21, 22, 23, 24, 25, 9, 10, 11]
        );
    });
}

#[test]
fn asynchronous_adapters_resume_pending_short_io() {
    block_on(async {
        let mut storage = PendingIo::new((0..12).collect());
        {
            let blocks = BlockIo::<_, 4>::new(&mut storage, 3).unwrap();
            let mut bytes = ByteCursor::new(blocks).unwrap();

            bytes.seek(std::io::SeekFrom::Start(3)).await.unwrap();
            bytes.write_all(&[20, 21, 22, 23, 24, 25]).await.unwrap();
            bytes.flush().await.unwrap();
            bytes.seek(std::io::SeekFrom::Start(2)).await.unwrap();

            let mut output = [0; 8];
            bytes.read_exact(&mut output).await.unwrap();
            assert_eq!(output, [2, 20, 21, 22, 23, 24, 25, 9]);
        }
        assert_eq!(
            storage.inner.into_inner(),
            [0, 1, 2, 20, 21, 22, 23, 24, 25, 9, 10, 11]
        );
    });
}
