// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::io::{self, Cursor, SeekFrom};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_verity::traits::tokio::{
    Format as _, Geometry, Open as _, OpenHashes as _, Scale as _, Slice as _,
};
use devmap_verity::{Hashes, Options, Scheme};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, ReadBuf};

struct Short(Cursor<Vec<u8>>);

impl AsyncRead for Short {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, output)
    }
}

impl Geometry for Short {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::new(512).unwrap())
    }

    fn count(&mut self) -> Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(1)))
    }
}

#[tokio::test]
async fn tokio_uses_the_same_format_and_open_workflow() {
    let data: Vec<_> = (0usize..257 * 512)
        .map(|index| u8::try_from(index % 251).expect("modulo 251 fits in u8"))
        .collect();
    let block_size = NonZeroU32::new(512).unwrap();
    let input = Cursor::new(&data).scale(block_size).await.unwrap();
    let mut hashes = Cursor::new(Vec::new()).scale(block_size).await.unwrap();
    let (_, root) = Scheme::default()
        .format(input, &mut hashes, [3; 16])
        .await
        .unwrap();
    hashes.seek(SeekFrom::Start(0)).await.unwrap();

    let mut device = Options::default()
        .open(
            Cursor::new(data.clone()),
            Hashes::open(hashes).await.unwrap(),
            &root,
        )
        .await
        .unwrap();
    device.seek(SeekFrom::Start(511)).await.unwrap();
    let mut output = [0; 1026];
    device.read_exact(&mut output).await.unwrap();
    assert_eq!(&output, &data[511..1537]);
}

#[tokio::test]
async fn asynchronous_format_rejects_short_input_and_leaves_trailing_bytes_unread() {
    let block_size = NonZeroU32::new(512).unwrap();
    let hashes = Cursor::new(Vec::new()).scale(block_size).await.unwrap();
    let error = Scheme::default()
        .format(Short(Cursor::new(vec![0; 511])), hashes, [0; 16])
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    let mut input = Cursor::new(vec![0; 513]);
    let data = (&mut input)
        .slice(0..512)
        .await
        .unwrap()
        .scale(block_size)
        .await
        .unwrap();
    let hashes = Cursor::new(Vec::new()).scale(block_size).await.unwrap();
    Scheme::default()
        .format(data, hashes, [0; 16])
        .await
        .unwrap();
    assert_eq!(input.position(), 512);
}

// A seekable endpoint that suspends every transfer and supplies short reads.
struct Delayed {
    inner: Cursor<Vec<u8>>,
    pending_seek: Option<u64>,
    ready: bool,
    read_bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_read: std::sync::Arc<std::sync::atomic::AtomicBool>,
    fail_seek: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Delayed {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            pending_seek: None,
            ready: false,
            read_bytes: std::sync::Arc::default(),
            fail_read: std::sync::Arc::default(),
            fail_seek: std::sync::Arc::default(),
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

impl AsyncRead for Delayed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::sync::atomic::Ordering::Relaxed;
        if self.pause(cx) {
            return Poll::Pending;
        }
        if self.fail_read.swap(false, Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected read error",
            )));
        }
        let mut bytes = [0; 31];
        let limit = bytes.len().min(output.remaining());
        let count = std::io::Read::read(&mut self.inner, &mut bytes[..limit])?;
        output.put_slice(&bytes[..count]);
        self.read_bytes.fetch_add(count, Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncSeek for Delayed {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        use std::sync::atomic::Ordering::Relaxed;
        if self.fail_seek.swap(false, Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected seek error",
            ));
        }
        assert!(self.pending_seek.is_none());
        let next = match position {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.inner.position()) + i128::from(n),
            SeekFrom::End(n) => self.inner.get_ref().len() as i128 + i128::from(n),
        };
        self.pending_seek = Some(u64::try_from(next).map_err(|_| io::ErrorKind::InvalidInput)?);
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        if self.pending_seek.is_some() && self.pause(cx) {
            return Poll::Pending;
        }
        if let Some(position) = self.pending_seek.take() {
            self.inner.set_position(position);
        }
        Poll::Ready(Ok(self.inner.position()))
    }
}

impl Geometry for Delayed {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }

    fn count(&mut self) -> Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(std::future::ready(Ok(self.inner.get_ref().len() as u64)))
    }
}

async fn image(blocks: usize) -> (Vec<u8>, Vec<u8>, Box<[u8]>) {
    let data: Vec<_> = (0..blocks * 512)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    let block_size = NonZeroU32::new(512).unwrap();
    let input = Cursor::new(&data).scale(block_size).await.unwrap();
    let mut output = Cursor::new(Vec::new()).scale(block_size).await.unwrap();
    let (_, root) = Scheme::default()
        .format(input, &mut output, [7; 16])
        .await
        .unwrap();
    (data, output.into_inner().into_inner(), root)
}

#[tokio::test]
async fn borrowed_endpoints_resume_cancelled_reads_with_smaller_buffers() {
    use std::future::poll_fn;
    use std::sync::atomic::Ordering::Relaxed;

    for cancel_in_hashes in [false, true] {
        let (bytes, storage, root) = image(257).await;
        let mut data = Delayed::new(bytes.clone());
        let mut storage = Delayed::new(storage);
        let data_reads = data.read_bytes.clone();
        let hash_reads = storage.read_bytes.clone();
        let hashes = Hashes::open(&mut storage).await.unwrap();
        hash_reads.store(0, Relaxed);
        let mut device = Options::default()
            .open(&mut data, hashes, &root)
            .await
            .unwrap();
        assert_eq!(data_reads.load(Relaxed), 0);
        assert_eq!(hash_reads.load(Relaxed), 0);

        poll_fn(|cx| {
            let mut bytes = [0xaa; 100];
            let mut output = ReadBuf::new(&mut bytes);
            match Pin::new(&mut device).poll_read(cx, &mut output) {
                Poll::Pending => {
                    assert_eq!(output.filled().len(), 0);
                    assert_eq!(bytes, [0xaa; 100]);
                    if !cancel_in_hashes || hash_reads.load(Relaxed) > 0 {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }
                Poll::Ready(_) => panic!("expected cancellation before completion"),
            }
        })
        .await;
        assert_eq!(device.hashes().uuid(), [7; 16]);
        assert_eq!(
            device
                .seek(SeekFrom::Start(512))
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        let mut first = [0; 1];
        device.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [bytes[0]]);
        let mut rest = Vec::new();
        device.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, bytes[1..]);
    }
}

#[tokio::test]
async fn asynchronous_failures_clear_progress_without_exposing_unauthenticated_bytes() {
    use std::sync::atomic::Ordering::Relaxed;

    for fail_hashes in [false, true] {
        for seek_error in [false, true] {
            let (bytes, storage, root) = image(3).await;
            let mut data = Delayed::new(bytes.clone());
            let mut storage = Delayed::new(storage);
            let flag = match (fail_hashes, seek_error) {
                (false, false) => data.fail_read.clone(),
                (false, true) => data.fail_seek.clone(),
                (true, false) => storage.fail_read.clone(),
                (true, true) => storage.fail_seek.clone(),
            };
            let hashes = Hashes::open(&mut storage).await.unwrap();
            let mut device = Options::default()
                .open(&mut data, hashes, &root)
                .await
                .unwrap();
            flag.store(true, Relaxed);
            let mut output = [0xaa; 17];
            assert_eq!(
                device.read(&mut output).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(output, [0xaa; 17]);
            assert_eq!(device.stream_position().await.unwrap(), 0);
            device.read_exact(&mut output).await.unwrap();
            assert_eq!(output, bytes[..17]);
        }
    }
}

#[tokio::test]
async fn authentication_failure_cannot_reuse_an_old_data_cache_entry() {
    let (bytes, storage, root) = image(3).await;
    let mut corrupt = bytes.clone();
    corrupt[512] ^= 1;
    let mut data = Delayed::new(corrupt);
    let mut storage = Delayed::new(storage);
    let hashes = Hashes::open(&mut storage).await.unwrap();
    let mut device = Options::default()
        .open(&mut data, hashes, &root)
        .await
        .unwrap();
    let mut output = [0; 17];
    device.read_exact(&mut output).await.unwrap();
    assert_eq!(output, bytes[..17]);
    device.seek(SeekFrom::Start(512)).await.unwrap();
    output.fill(0xaa);
    assert_eq!(
        device.read(&mut output).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(output, [0xaa; 17]);
    assert_eq!(device.stream_position().await.unwrap(), 512);
    device.rewind().await.unwrap();
    device.read_exact(&mut output).await.unwrap();
    assert_eq!(output, bytes[..17]);
}

#[tokio::test]
async fn single_block_authentication_is_lazy_and_needs_no_tree() {
    use std::sync::atomic::Ordering::Relaxed;
    let (data, storage, mut root) = image(1).await;
    root[0] ^= 1;
    let storage = Delayed::new(storage);
    let hash_reads = storage.read_bytes.clone();
    let hashes = Hashes::open(storage).await.unwrap();
    hash_reads.store(0, Relaxed);
    let mut volume = Options::default()
        .open(Cursor::new(data), hashes, &root)
        .await
        .unwrap();
    assert_eq!(hash_reads.load(Relaxed), 0);
    assert_eq!(
        volume.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(hash_reads.load(Relaxed), 0);
}
