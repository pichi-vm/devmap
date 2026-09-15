// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]
#![allow(clippy::cast_possible_truncation)]

use std::io;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use devmap_snapshot::{
    Layer,
    traits::tokio::{Compact, Create, Geometry, Merge, Open, Readable, Scale, SyncData, Writable},
};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};

const SIZE: usize = 4096;
const CHUNK_SIZE_SECTORS: u32 = 8;
const CHUNK_SIZE: NonZeroU32 = NonZeroU32::new(CHUNK_SIZE_SECTORS).unwrap();

#[derive(Clone)]
struct Device {
    bytes: Arc<Mutex<Vec<u8>>>,
    writes: Arc<AtomicUsize>,
    syncs: Arc<AtomicUsize>,
    fail_sync_at: Arc<AtomicUsize>,
    position: u64,
    ready: bool,
}

impl Device {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
            writes: Arc::new(AtomicUsize::new(0)),
            syncs: Arc::new(AtomicUsize::new(0)),
            fail_sync_at: Arc::new(AtomicUsize::new(usize::MAX)),
            position: 0,
            ready: false,
        }
    }

    fn reopen(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            writes: self.writes.clone(),
            syncs: self.syncs.clone(),
            fail_sync_at: self.fail_sync_at.clone(),
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
        self.writes.fetch_add(1, Ordering::Relaxed);
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

impl SyncData for Device {
    fn sync_data(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async {
            tokio::task::yield_now().await;
            let sync = self.syncs.fetch_add(1, Ordering::Relaxed);
            if self.fail_sync_at.load(Ordering::Relaxed) == sync {
                return Err(io::Error::other("injected persistence failure"));
            }
            Ok(())
        })
    }
}

impl Geometry for Device {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }

    fn count(&mut self) -> Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(async {
            tokio::task::yield_now().await;
            Ok(self.bytes.lock().unwrap().len() as u64)
        })
    }
}

fn devices(chunks: u64) -> (Device, Device) {
    let origin_bytes = chunks * SIZE as u64;
    let cow_bytes = (chunks + 3) * SIZE as u64;
    (
        Device::new(vec![0; origin_bytes as usize]),
        Device::new(vec![0; cow_bytes as usize]),
    )
}

#[test]
fn tokio_files_need_no_adapter_type() {
    fn sync_capable<T: SyncData>() {}
    fn geometry_capable<T: Geometry>() {}
    fn create_capable<T: Create<tokio::fs::File, tokio::fs::File>>() {}
    fn open_capable<T: Open<tokio::fs::File, tokio::fs::File>>() {}
    fn layer_capable<T: AsyncRead + AsyncWrite + AsyncSeek + Geometry + SyncData>() {}

    sync_capable::<tokio::fs::File>();
    geometry_capable::<tokio::fs::File>();
    create_capable::<Layer<tokio::fs::File, tokio::fs::File>>();
    open_capable::<Layer<tokio::fs::File, tokio::fs::File>>();
    layer_capable::<Layer<tokio::fs::File, tokio::fs::File>>();
}

#[test]
fn async_operations_require_only_the_capabilities_they_use() {
    fn create<O, C>(
        origin: O,
        cow: C,
    ) -> impl std::future::Future<Output = io::Result<Layer<O, C>>> + Send
    where
        O: Geometry + Send,
        C: AsyncWrite + AsyncSeek + Geometry + SyncData + Unpin + Send,
    {
        Layer::create(origin, cow, CHUNK_SIZE)
    }

    fn open<O, C>(
        origin: O,
        cow: C,
    ) -> impl std::future::Future<Output = io::Result<Layer<O, C>>> + Send
    where
        O: Geometry + Send,
        C: AsyncRead + AsyncSeek + Geometry + Unpin + Send,
    {
        Layer::open(origin, cow)
    }

    fn persist<O, C>(
        layer: &mut Layer<O, C>,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        C: AsyncWrite + AsyncSeek + SyncData + Unpin + Send,
    {
        SyncData::sync_data(layer)
    }

    fn merge<O, C>(
        layer: &mut Layer<O, C>,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        O: AsyncWrite + AsyncSeek + SyncData + Unpin + Send + 'static,
        C: AsyncRead + AsyncWrite + AsyncSeek + SyncData + Unpin + Send + 'static,
    {
        Merge::merge(layer)
    }

    fn compact<O, C>(
        layer: &mut Layer<O, C>,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        O: AsyncRead + AsyncSeek + Unpin + Send,
        C: AsyncRead + AsyncSeek + Unpin + Send,
    {
        Compact::compact(layer, tokio::io::sink())
    }

    let _ = (
        create::<Device, Device>,
        open::<Device, Device>,
        persist::<Device, Device>,
        merge::<Device, Device>,
        compact::<Device, Device>,
    );
}

#[tokio::test]
async fn tokio_uses_the_same_type_and_workflow() {
    let (origin, cow) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    layer
        .seek(io::SeekFrom::Start(SIZE as u64 + 9))
        .await
        .unwrap();
    layer.write_all(&[1, 2, 3, 4]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);

    let mut opened = Layer::open(origin_again, cow_again).await.unwrap();
    opened
        .seek(io::SeekFrom::Start(SIZE as u64 + 7))
        .await
        .unwrap();
    let mut bytes = [0; 8];
    opened.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [0, 0, 1, 2, 3, 4, 0, 0]);
}

#[tokio::test]
async fn layers_nest_to_runtime_depth_through_an_async_erased_source() {
    let mut lower: Box<dyn Readable> = Box::new(Device::new(vec![0; 4 * SIZE]));

    for (index, byte) in [(0_u64, 0x11), (1, 0x22), (2, 0x33)] {
        let cow = Device::new(vec![0; 7 * SIZE]);
        let mut layer = Layer::create(lower, cow, CHUNK_SIZE).await.unwrap();
        layer
            .seek(io::SeekFrom::Start(index * SIZE as u64))
            .await
            .unwrap();
        layer.write_all(&vec![byte; SIZE]).await.unwrap();
        lower = Box::new(layer);
    }

    for (index, byte) in [(0_u64, 0x11), (1, 0x22), (2, 0x33)] {
        lower
            .seek(io::SeekFrom::Start(index * SIZE as u64))
            .await
            .unwrap();
        let mut contents = vec![0; SIZE];
        lower.read_exact(&mut contents).await.unwrap();
        assert!(contents.iter().all(|value| *value == byte));
    }
}

#[tokio::test]
async fn an_async_erased_lower_layer_can_receive_a_merge() {
    let mut lower = Layer::create(
        Device::new(vec![0; 4 * SIZE]),
        Device::new(vec![0; 7 * SIZE]),
        CHUNK_SIZE,
    )
    .await
    .unwrap();
    lower.write_all(&vec![0x11; SIZE]).await.unwrap();
    let lower: Box<dyn Writable> = Box::new(lower);

    let mut upper = Layer::create(lower, Device::new(vec![0; 7 * SIZE]), CHUNK_SIZE)
        .await
        .unwrap();
    upper.seek(io::SeekFrom::Start(SIZE as u64)).await.unwrap();
    upper.write_all(&vec![0x22; SIZE]).await.unwrap();
    upper.merge().await.unwrap();

    upper.seek(io::SeekFrom::Start(0)).await.unwrap();
    let mut contents = vec![0; 2 * SIZE];
    upper.read_exact(&mut contents).await.unwrap();
    assert!(contents[..SIZE].iter().all(|byte| *byte == 0x11));
    assert!(contents[SIZE..].iter().all(|byte| *byte == 0x22));
}

#[tokio::test]
async fn async_read_only_endpoints_can_be_opened_and_compacted() {
    let (origin, cow) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    layer.seek(io::SeekFrom::Start(SIZE as u64)).await.unwrap();
    layer.write_all(&vec![0x5a; SIZE]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);

    let origin: Box<dyn Readable> = Box::new(origin_again);
    let cow: Box<dyn Readable> = Box::new(cow_again);
    let mut layer = Layer::open(origin, cow).await.unwrap();
    layer.seek(io::SeekFrom::Start(SIZE as u64)).await.unwrap();
    let mut bytes = vec![0; SIZE];
    layer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|value| *value == 0x5a));
    layer.compact(tokio::io::sink()).await.unwrap();
}

#[tokio::test]
async fn async_layer_checks_synchronous_endpoint_geometry() {
    let origin = Device::new(vec![0; 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .await
        .unwrap();
    let cow = Device::new(vec![0; 2 * 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .await
        .unwrap();
    let error = Layer::create(origin, cow, NonZeroU32::new(8).unwrap())
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn async_io_crosses_chunk_boundaries() {
    let (origin, cow) = devices(3);
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
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
async fn async_writes_only_promote_differences_from_the_lower_chunk() {
    let (origin, cow) = devices(3);
    origin.bytes.lock().unwrap()[..SIZE].fill(0x55);
    let writes = cow.writes.clone();
    let cow_bytes = cow.bytes.clone();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    let initialized = writes.load(Ordering::Relaxed);

    layer.write_all(&vec![0x55; SIZE]).await.unwrap();
    layer
        .seek(io::SeekFrom::Start(SIZE as u64 + 7))
        .await
        .unwrap();
    layer.write_all(&[0; 19]).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), initialized);

    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    layer.write_all(&vec![0xaa; SIZE]).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), initialized + 1);

    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    layer.write_all(&vec![0xaa; SIZE]).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), initialized + 2);

    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    layer.write_all(&vec![0; SIZE]).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), initialized + 3);
    layer.sync_data().await.unwrap();
    drop(layer);
    assert_eq!(
        u64::from_le_bytes(
            cow_bytes.lock().unwrap()[SIZE + 8..SIZE + 16]
                .try_into()
                .unwrap()
        ),
        2
    );
}

#[tokio::test]
async fn async_zero_writes_need_no_promotion_capacity() {
    let origin = devmap_zero::Zero::new((2 * SIZE + 17) as u64);
    let cow = Device::new(vec![0; 2 * SIZE]);
    let writes = cow.writes.clone();
    let bytes = cow.bytes.clone();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    let initialized = writes.load(Ordering::Relaxed);

    layer.write_all(&vec![0; 2 * SIZE + 17]).await.unwrap();
    assert_eq!(
        layer.stream_position().await.unwrap(),
        (2 * SIZE + 17) as u64
    );
    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    let error = layer.write_all(&vec![1; SIZE]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    layer.write_all(&vec![0; SIZE]).await.unwrap();
    layer.sync_data().await.unwrap();

    assert_eq!(writes.load(Ordering::Relaxed), initialized);
    assert!(bytes.lock().unwrap()[SIZE..].iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn async_compact_writes_an_exact_size_store() {
    let (origin, cow) = devices(4);
    origin.bytes.lock().unwrap().fill(0x11);
    let origin_again = origin.reopen();
    let output = Device::new(Vec::new());
    let output_again = output.reopen();
    let output_bytes = output.bytes.clone();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();

    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    layer.write_all(&vec![0xaa; SIZE]).await.unwrap();
    layer.seek(io::SeekFrom::Start(0)).await.unwrap();
    layer.write_all(&vec![0x11; SIZE]).await.unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    layer.write_all(&vec![0xcc; SIZE]).await.unwrap();
    layer.compact(output).await.unwrap();
    drop(layer);

    assert_eq!(output_bytes.lock().unwrap().len(), 3 * SIZE);
    let mut compact = Layer::open(origin_again, output_again).await.unwrap();
    compact
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    let mut bytes = vec![0; SIZE];
    compact.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0xcc));
}

#[tokio::test]
async fn end_relative_seek_discovers_the_origin_size_asynchronously() {
    let (origin, cow) = devices(3);
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    assert_eq!(
        layer.seek(io::SeekFrom::End(-1)).await.unwrap(),
        3 * SIZE as u64 - 1
    );
}

#[tokio::test]
async fn end_relative_seek_completes_from_the_cached_size() {
    use std::future::poll_fn;

    let (origin, cow) = devices(3);
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    Pin::new(&mut layer)
        .start_seek(io::SeekFrom::End(-1))
        .unwrap();
    assert_eq!(
        poll_fn(|cx| match Pin::new(&mut layer).poll_complete(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => panic!("cached end-relative seek unexpectedly became pending"),
        })
        .await
        .unwrap(),
        3 * SIZE as u64 - 1
    );
}

#[tokio::test]
async fn async_merge_persists_and_retires() {
    let (origin, cow) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    layer.write_all(&vec![0xcc; SIZE]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);
    let mut layer = Layer::open(origin_again, cow_again).await.unwrap();
    layer.merge().await.unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    let mut bytes = vec![0; SIZE];
    layer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0xcc));
}

#[tokio::test]
async fn async_cow_retirement_failure_poisons_the_layer() {
    let (origin, cow) = devices(4);
    cow.fail_sync_at.store(3, Ordering::Relaxed);
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    layer.write_all(&vec![0xcc; SIZE]).await.unwrap();

    assert!(layer.merge().await.is_err());
    assert!(layer.read_exact(&mut [0]).await.is_err());
}

#[tokio::test]
async fn abandoned_merge_can_be_resumed() {
    use std::future::{Future as _, poll_fn};

    let (origin, cow) = devices(4);
    let origin_again = origin.reopen();
    let cow_again = cow.reopen();
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    layer.write_all(&vec![0xcc; SIZE]).await.unwrap();
    layer.sync_data().await.unwrap();
    drop(layer);

    let mut layer = Layer::open(origin_again, cow_again).await.unwrap();
    let mut merge = Box::pin(Merge::merge(&mut layer));
    poll_fn(|cx| match merge.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("merge unexpectedly completed: {result:?}"),
    })
    .await;
    drop(merge);

    layer.merge().await.unwrap();
    layer
        .seek(io::SeekFrom::Start(2 * SIZE as u64))
        .await
        .unwrap();
    let mut bytes = vec![0; SIZE];
    layer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0xcc));
}

#[tokio::test]
async fn abandoned_write_must_be_resumed_with_the_same_input() {
    use std::future::poll_fn;
    let (origin, cow) = devices(2);
    let mut layer = Layer::create(origin, cow, CHUNK_SIZE).await.unwrap();
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
