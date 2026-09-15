// SPDX-License-Identifier: Apache-2.0

use std::future::{Future as _, poll_fn};
use std::io::{self, Cursor, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_verity::{Hashes, traits::tokio::OpenHashes as _};
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, ReadBuf};

mod common;

#[tokio::test]
async fn tokio_files_work_without_a_hash_implementation() {
    use std::io::Write as _;

    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&common::header("sha256")).unwrap();
    let mut file = tokio::fs::File::from_std(file);
    let hashes = Hashes::open(&mut file).await.unwrap();
    assert_eq!(hashes.uuid(), [0x5a; 16]);
    assert_eq!(hashes.into_inner().stream_position().await.unwrap(), 512);
}

// No Geometry or synchronous I/O traits: opening needs only Tokio transport.
struct Source {
    inner: Cursor<Vec<u8>>,
    ready: bool,
}

impl AsyncRead for Source {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.ready = !self.ready;
        if self.ready {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        assert!(
            self.inner.position() < 512,
            "inspection read beyond the record"
        );
        let limit = output.remaining().min(7);
        let mut bytes = [0; 7];
        let count = std::io::Read::read(&mut self.inner, &mut bytes[..limit])?;
        output.put_slice(&bytes[..count]);
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for Source {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        assert!(matches!(position, SeekFrom::Start(0)));
        self.inner.set_position(0);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.inner.position()))
    }
}

#[tokio::test]
async fn tokio_only_build_inspects_every_algorithm_with_borrowed_storage() {
    for &(name, algorithm, _) in common::ALGORITHMS {
        let mut source = Source {
            inner: Cursor::new(common::header(name).to_vec()),
            ready: false,
        };
        let hashes = Hashes::open(&mut source).await.unwrap();
        assert_eq!(hashes.parameters().algorithm(), algorithm);
        assert_eq!(hashes.into_inner().inner.position(), 512);
    }
}

#[tokio::test]
async fn cancelled_header_open_can_restart_at_zero() {
    let mut source = Source {
        inner: Cursor::new(common::header("sha256").to_vec()),
        ready: false,
    };
    let mut opening = Box::pin(Hashes::open(&mut source));
    poll_fn(|cx| match opening.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("expected a pending transport"),
    })
    .await;
    drop(opening);
    let hashes = Hashes::open(&mut source).await.unwrap();
    assert_eq!(hashes.parameters().salt(), [1, 2, 3]);
    assert_eq!(hashes.into_inner().inner.position(), 512);
}

#[tokio::test]
async fn async_header_errors_preserve_validation_and_transport_kinds() {
    let mut bytes = common::header("sha256");
    bytes[80..82].copy_from_slice(&257u16.to_le_bytes());
    assert_eq!(
        Hashes::open(Cursor::new(bytes)).await.err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        Hashes::open(Cursor::new(&bytes[..511]))
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    let mut storage = Cursor::new(common::header("sha256"));
    storage.seek(SeekFrom::Start(123)).await.unwrap();
    let hashes = Hashes::open(storage).await.unwrap();
    assert_eq!(hashes.into_inner().position(), 512);
}
