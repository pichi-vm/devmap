// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]
#![allow(clippy::cast_possible_truncation)]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use devmap_snapshot::{AsyncSyncData, ChunkSize, Layer};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};

const SIZE: usize = 4096;

#[derive(Clone)]
struct Device {
    bytes: Arc<Mutex<Vec<u8>>>,
    position: u64,
    ready: bool,
}

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
            position: 0,
            ready: false,
        }
    }

    fn reopen(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            position: 0,
            ready: false,
        }
    }

    fn pause(&mut self, cx: &Context<'_>) -> bool {
        self.ready = !self.ready;
        if self.ready {
            cx.waker().wake_by_ref();
        }
        self.ready
    }
}

impl AsyncRead for Device {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pause(cx) {
            return Poll::Pending;
        }
        let bytes = self.bytes.lock().unwrap();
        let start = usize::try_from(self.position)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let count = output.remaining().min(bytes.len() - start);
        output.put_slice(&bytes[start..start + count]);
        drop(bytes);
        self.position += count as u64;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Device {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pause(cx) {
            return Poll::Pending;
        }
        let start = usize::try_from(self.position).map_err(|_| io::Error::other("position"))?;
        let mut bytes = self.bytes.lock().unwrap();
        if bytes.len() < start + input.len() {
            bytes.resize(start + input.len(), 0);
        }
        bytes[start..start + input.len()].copy_from_slice(input);
        drop(bytes);
        self.position += input.len() as u64;
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pause(cx) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncSeek for Device {
    fn start_seek(mut self: Pin<&mut Self>, seek: io::SeekFrom) -> io::Result<()> {
        let length = self.bytes.lock().unwrap().len() as u64;
        let next = match seek {
            io::SeekFrom::Start(position) => i128::from(position),
            io::SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            io::SeekFrom::End(delta) => i128::from(length) + i128::from(delta),
        };
        self.position = u64::try_from(next).map_err(|_| io::ErrorKind::InvalidInput)?;
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        if self.pause(cx) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(self.position))
        }
    }
}

impl AsyncSyncData for Device {
    async fn sync_data(&mut self) -> io::Result<()> {
        tokio::task::yield_now().await;
        Ok(())
    }
}

fn size() -> ChunkSize {
    ChunkSize::from_sectors(8).unwrap()
}

fn devices(chunks: u64) -> (Device, Device, u64, u64) {
    let origin_bytes = chunks * SIZE as u64;
    let cow_bytes = size().cow_chunks(chunks).unwrap() * SIZE as u64;
    (
        Device::new(vec![0; origin_bytes as usize]),
        Device::new(vec![0; cow_bytes as usize]),
        origin_bytes,
        cow_bytes,
    )
}

#[test]
fn tokio_files_need_no_adapter_type() {
    fn sync_capable<T: AsyncSyncData>() {}
    fn layer_capable<T: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData>() {}

    sync_capable::<tokio::fs::File>();
    layer_capable::<Layer<tokio::fs::File, tokio::fs::File>>();
}

#[tokio::test]
async fn tokio_uses_the_same_type_and_workflow() {
    let (origin, cow, origin_bytes, cow_bytes) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, size()).unwrap();
    layer
        .seek(io::SeekFrom::Start(SIZE as u64 + 9))
        .await
        .unwrap();
    layer.write_all(&[1, 2, 3, 4]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);

    let mut opened = Layer::open(origin_again, cow_again, origin_bytes, cow_bytes).unwrap();
    opened
        .seek(io::SeekFrom::Start(SIZE as u64 + 7))
        .await
        .unwrap();
    let mut bytes = [0; 8];
    opened.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [0, 0, 1, 2, 3, 4, 0, 0]);
}

#[tokio::test]
async fn async_io_crosses_chunk_boundaries() {
    let (origin, cow, origin_bytes, cow_bytes) = devices(3);
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, size()).unwrap();
    layer
        .seek(io::SeekFrom::Start(SIZE as u64 - 2))
        .await
        .unwrap();
    layer.write_all(&[1, 2, 3, 4, 5]).await.unwrap();
    layer.sync_data().await.unwrap();
    layer
        .seek(io::SeekFrom::Start(SIZE as u64 - 2))
        .await
        .unwrap();
    let mut bytes = [0; 5];
    layer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn async_merge_persists_and_retires() {
    let (origin, cow, origin_bytes, cow_bytes) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, size()).unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    layer.write_all(&vec![0xcc; SIZE]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);
    let layer = Layer::open(origin_again, cow_again, origin_bytes, cow_bytes).unwrap();
    let (mut origin, _) = layer.merge().await.unwrap();
    origin
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    let mut bytes = vec![0; SIZE];
    origin.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0xcc));
}

#[tokio::test]
async fn abandoned_write_must_be_resumed_with_the_same_input() {
    use std::future::poll_fn;
    let (origin, cow, origin_bytes, cow_bytes) = devices(2);
    let mut layer = Layer::create(origin, cow, origin_bytes, cow_bytes, size()).unwrap();
    let first = [1; 32];
    poll_fn(|cx| match Pin::new(&mut layer).poll_write(cx, &first) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("operation unexpectedly completed: {result:?}"),
    })
    .await;
    let error = poll_fn(|cx| match Pin::new(&mut layer).poll_write(cx, &[2; 32]) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => Poll::Pending,
    })
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}
