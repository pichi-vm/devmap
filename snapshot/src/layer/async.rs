// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use devmap_core::traits::tokio::{Geometry, SyncData};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};

use crate::chunk_size::{ChunkSize, Header};

use super::state::{State, buffer};
use crate::traits::tokio::{Compact, Create, Merge, Open};

use super::Layer;

fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "another asynchronous layer operation is in progress",
    )
}

pub(super) struct Core<O, C> {
    origin: O,
    cow: C,
    origin_bytes: u64,
    cow_bytes: u64,
    chunk_size: ChunkSize,
    state: State,
    failed: bool,
}

pub(super) enum Output {
    Read(Vec<u8>),
    Write(usize),
    Flush,
    Merge,
}

pub(super) type Operation<O, C> =
    Pin<Box<dyn Future<Output = (Core<O, C>, io::Result<Output>)> + Send>>;

pub(super) enum Pending<O, C> {
    Read(Operation<O, C>),
    Write {
        input: Vec<u8>,
        operation: Operation<O, C>,
    },
    Flush(Operation<O, C>),
    Merge(Operation<O, C>),
}

impl<O, C> Core<O, C> {
    fn chunk_bytes(&self) -> u64 {
        self.chunk_size.bytes()
    }

    fn state_mut(&mut self) -> io::Result<&mut State> {
        if self.failed {
            Err(Layer::<O, C>::poisoned())
        } else {
            Ok(&mut self.state)
        }
    }

    fn fatal(&mut self, error: io::Error) -> io::Error {
        self.failed = true;
        error
    }
}

async fn read_at<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
    position: u64,
    bytes: &mut [u8],
) -> io::Result<()> {
    reader.seek(io::SeekFrom::Start(position)).await?;
    reader.read_exact(bytes).await.map(|_| ())
}

async fn flush_cow<C>(
    cow: &mut C,
    state: &mut State,
    failed: &mut bool,
    chunk_size: ChunkSize,
) -> io::Result<()>
where
    C: AsyncWrite + AsyncSeek + SyncData + Unpin,
{
    if *failed {
        return Err(Layer::<(), ()>::poisoned());
    }
    if state.dirty {
        if let Err(error) = cow.sync_data().await {
            *failed = true;
            return Err(error);
        }
        let chunk = state.current_metadata_chunk()?;
        let metadata = state.buffer.clone();
        let position = chunk_size.offset(chunk)?;
        let result = async {
            cow.seek(io::SeekFrom::Start(position)).await?;
            cow.write_all(&metadata).await
        }
        .await;
        if let Err(error) = result {
            *failed = true;
            return Err(error);
        }
        state.dirty = false;
    }
    let result = cow.flush().await;
    if let Err(error) = result {
        *failed = true;
        Err(error)
    } else {
        Ok(())
    }
}

impl<O, C> Create<O, C> for Layer<O, C>
where
    O: Geometry + Send,
    C: AsyncWrite + AsyncSeek + Geometry + SyncData + Unpin + Send,
{
    async fn create(
        mut origin: O,
        mut cow: C,
        chunk_size: std::num::NonZeroU32,
    ) -> io::Result<Self> {
        let origin_block_size = origin.block_size()?;
        let cow_block_size = cow.block_size()?;
        let origin_bytes = origin
            .count()
            .await?
            .checked_mul(u64::from(origin_block_size.get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "origin geometry overflows")
            })?;
        let cow_bytes = cow
            .count()
            .await?
            .checked_mul(u64::from(cow_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "COW geometry overflows"))?;
        let chunk_size = ChunkSize::new(chunk_size)?;
        let block_size = Self::combined_block_size(origin_block_size, cow_block_size)?;
        Self::validate_geometry(
            origin_bytes,
            cow_bytes,
            chunk_size,
            origin_block_size,
            cow_block_size,
            block_size,
        )?;
        let state = State::new(chunk_size.len())?;
        let mut core = Core {
            origin,
            cow,
            origin_bytes,
            cow_bytes,
            chunk_size,
            state,
            failed: false,
        };
        core.initialize().await?;
        Ok(Layer::from_parts(
            core.origin,
            core.cow,
            core.origin_bytes,
            core.cow_bytes,
            core.chunk_size,
            block_size,
            core.state,
        ))
    }
}

impl<O, C> Open<O, C> for Layer<O, C>
where
    O: Geometry + Send,
    C: AsyncRead + AsyncSeek + Geometry + Unpin + Send,
{
    async fn open(mut origin: O, mut cow: C) -> io::Result<Self> {
        let origin_block_size = origin.block_size()?;
        let cow_block_size = cow.block_size()?;
        let origin_bytes = origin
            .count()
            .await?
            .checked_mul(u64::from(origin_block_size.get()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "origin geometry overflows")
            })?;
        let cow_bytes = cow
            .count()
            .await?
            .checked_mul(u64::from(cow_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "COW geometry overflows"))?;
        let block_size = Self::combined_block_size(origin_block_size, cow_block_size)?;
        if cow_bytes < Header::LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "copy-on-write store is too short",
            ));
        }
        let mut header = Header::default();
        read_at(&mut cow, 0, header.as_mut()).await?;
        let chunk_size = header.chunk_size()?;
        Self::validate_geometry(
            origin_bytes,
            cow_bytes,
            chunk_size,
            origin_block_size,
            cow_block_size,
            block_size,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let chunk_bytes = chunk_size.bytes();
        let allocation_size = chunk_size.len();
        let mut state = State::new(allocation_size)?;
        let cow_chunks = cow_bytes / chunk_bytes;
        let mut area = 0;
        loop {
            let chunk = state.metadata_chunk(area)?;
            if chunk >= cow_chunks {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot metadata walk leaves the store",
                ));
            }
            let mut bytes = buffer(allocation_size)?;
            read_at(&mut cow, chunk_size.offset(chunk)?, &mut bytes).await?;
            state.buffer.copy_from_slice(&bytes);
            match state.absorb_area(area, cow_chunks) {
                Ok(true) => break,
                Ok(false) => {
                    area = area.checked_add(1).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot metadata area overflows",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Self::from_parts(
            origin,
            cow,
            origin_bytes,
            cow_bytes,
            chunk_size,
            block_size,
            state,
        ))
    }
}

impl<O, C> Merge for Layer<O, C>
where
    O: AsyncWrite + AsyncSeek + SyncData + Unpin + Send + 'static,
    C: AsyncRead + AsyncWrite + AsyncSeek + SyncData + Unpin + Send + 'static,
{
    fn merge(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        std::future::poll_fn(move |cx| {
            if self.pending.is_some() && !matches!(self.pending, Some(Pending::Merge(_))) {
                return Poll::Ready(Err(busy()));
            }
            if self.pending.is_none() {
                let mut core = match self.take_core() {
                    Ok(core) => core,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                self.pending = Some(Pending::Merge(Box::pin(async move {
                    let result = core.merge().await.map(|()| Output::Merge);
                    (core, result)
                })));
            }
            match self.finish_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(Output::Merge)) => Poll::Ready(Ok(())),
                Poll::Ready(Ok(_)) => Poll::Ready(Err(busy())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            }
        })
    }
}

impl<O, C> Compact for Layer<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin + Send,
    C: AsyncRead + AsyncSeek + Unpin + Send,
{
    async fn compact(&mut self, mut output: impl AsyncWrite + Unpin + Send) -> io::Result<()> {
        self.ready()?;

        let chunk_bytes = self.chunk_bytes();
        let chunk_usize = self.chunk_size.len();
        let per_area = chunk_bytes / State::EXCEPTION_LEN as u64;
        let mut upper = buffer(chunk_usize)?;
        let mut lower = buffer(chunk_usize)?;
        let mut metadata = buffer(chunk_usize)?;
        let encoded = Header::new(self.chunk_size);
        upper[..Header::LEN].copy_from_slice(encoded.as_ref());
        output.write_all(&upper).await?;

        let mut previous = None;
        let mut metadata_chunk = 1_u64;
        loop {
            metadata.fill(0);
            let mut retained = 0_u64;
            let mut exhausted = false;
            while retained < per_area {
                let Some((origin, cow)) = self.state_mut()?.next_exception(previous) else {
                    exhausted = true;
                    break;
                };
                previous = Some(origin);
                let origin_offset = self.chunk_size.offset(origin)?;
                if origin_offset >= self.origin_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the store holds an exception outside its origin",
                    ));
                }
                let valid = usize::try_from((self.origin_bytes - origin_offset).min(chunk_bytes))
                    .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
                let cow_offset = self.chunk_size.offset(cow)?;
                read_at(self.cow_mut()?, cow_offset, &mut upper).await?;
                read_at(self.origin_mut()?, origin_offset, &mut lower[..valid]).await?;
                if upper[..valid] == lower[..valid] {
                    continue;
                }

                let destination = metadata_chunk
                    .checked_add(1)
                    .and_then(|chunk| chunk.checked_add(retained))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "compact geometry overflows")
                    })?;
                let slot = usize::try_from(retained)
                    .map_err(|_| io::Error::other("metadata slot exceeds usize"))?
                    * State::EXCEPTION_LEN;
                metadata[slot..slot + 8].copy_from_slice(&origin.to_le_bytes());
                metadata[slot + 8..slot + State::EXCEPTION_LEN]
                    .copy_from_slice(&destination.to_le_bytes());
                retained += 1;
            }

            output.write_all(&metadata).await?;
            for slot in 0..retained {
                let metadata_offset = usize::try_from(slot)
                    .map_err(|_| io::Error::other("metadata slot exceeds usize"))?
                    * State::EXCEPTION_LEN;
                let origin = u64::from_le_bytes(
                    metadata[metadata_offset..metadata_offset + 8]
                        .try_into()
                        .map_err(|_| io::Error::other("metadata entry is truncated"))?,
                );
                let cow = self.state_mut()?.lookup(origin).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "snapshot exception disappeared")
                })?;
                let cow_offset = self.chunk_size.offset(cow)?;
                read_at(self.cow_mut()?, cow_offset, &mut upper).await?;
                output.write_all(&upper).await?;
            }

            if exhausted {
                return output.flush().await;
            }
            metadata_chunk = metadata_chunk.checked_add(per_area + 1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "compact geometry overflows")
            })?;
        }
    }
}

impl<O, C: AsyncWrite + AsyncSeek + Unpin> Core<O, C> {
    async fn put_cow(&mut self, chunk: u64, bytes: &[u8]) -> io::Result<()> {
        let position = self.chunk_size.offset(chunk)?;
        let result = async {
            self.cow.seek(io::SeekFrom::Start(position)).await?;
            self.cow.write_all(bytes).await
        }
        .await;
        result.map_err(|error| self.fatal(error))
    }
}

impl<O, C: SyncData> Core<O, C> {
    async fn barrier(&mut self) -> io::Result<()> {
        let result = self.cow.sync_data().await;
        result.map_err(|error| self.fatal(error))
    }
}

impl<O, C: AsyncWrite + AsyncSeek + SyncData + Unpin> Core<O, C> {
    async fn initialize(&mut self) -> io::Result<()> {
        let area = self.state_mut()?.current_metadata_chunk()?;
        let zeros = buffer(self.chunk_size.len())?;
        self.put_cow(area, &zeros).await?;
        self.barrier().await?;
        let mut header = zeros;
        let encoded = Header::new(self.chunk_size);
        header[..Header::LEN].copy_from_slice(encoded.as_ref());
        self.put_cow(0, &header).await?;
        let result = self.cow.flush().await;
        result.map_err(|error| self.fatal(error))
    }
}

impl<O: AsyncRead + AsyncSeek + Unpin, C: AsyncRead + AsyncSeek + Unpin> Core<O, C> {
    async fn read_prefix(&mut self, index: u64, bytes: &mut [u8]) -> io::Result<()> {
        let source = self.state_mut()?.lookup(index);
        if let Some(chunk) = source {
            let position = self.chunk_size.offset(chunk)?;
            read_at(&mut self.cow, position, bytes).await
        } else {
            let position = self.chunk_size.offset(index)?;
            read_at(&mut self.origin, position, bytes).await
        }
    }

    async fn read(&mut self, position: u64, maximum: usize) -> io::Result<Vec<u8>> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        if self.failed {
            return Err(Layer::<O, C>::poisoned());
        }
        let origin_bytes = self.origin_bytes;
        if position >= origin_bytes {
            return Ok(Vec::new());
        }
        let chunk_bytes = self.chunk_bytes();
        let index = position / chunk_bytes;
        let within = usize::try_from(position % chunk_bytes)
            .map_err(|_| io::Error::other("position exceeds usize"))?;
        let count = usize::try_from(
            (origin_bytes - position)
                .min(maximum as u64)
                .min(chunk_bytes - within as u64),
        )
        .map_err(|_| io::Error::other("read length exceeds usize"))?;
        let valid = usize::try_from((origin_bytes - index * chunk_bytes).min(chunk_bytes))
            .map_err(|_| io::Error::other("chunk length exceeds usize"))?;
        let mut chunk = buffer(self.chunk_size.len())?;
        self.read_prefix(index, &mut chunk[..valid]).await?;
        Ok(chunk[within..within + count].to_vec())
    }
}

impl<O, C> Core<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin,
    C: AsyncRead + AsyncWrite + AsyncSeek + SyncData + Unpin,
{
    async fn write_chunk(&mut self, index: u64, within: usize, input: &[u8]) -> io::Result<()> {
        let chunk_bytes = self.chunk_bytes();
        let chunk_usize = self.chunk_size.len();
        let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
            .map_err(|_| io::Error::other("chunk length exceeds usize"))?;

        if let Some(chunk) = self.state_mut()?.lookup(index) {
            if within == 0 && input.len() == chunk_usize {
                return self.put_cow(chunk, input).await;
            }
            let mut bytes = buffer(chunk_usize)?;
            let position = self.chunk_size.offset(chunk)?;
            read_at(&mut self.cow, position, &mut bytes).await?;
            bytes[within..within + input.len()].copy_from_slice(input);
            return self.put_cow(chunk, &bytes).await;
        }

        let mut bytes = buffer(chunk_usize)?;
        let position = self.chunk_size.offset(index)?;
        read_at(&mut self.origin, position, &mut bytes[..valid]).await?;
        if bytes[within..within + input.len()] == *input {
            return Ok(());
        }
        let promoted = if within == 0 && input.len() == chunk_usize {
            input
        } else {
            bytes[within..within + input.len()].copy_from_slice(input);
            &bytes
        };

        let cow_chunks = self.cow_bytes / self.chunk_bytes();
        let chunk = self.state_mut()?.plan(cow_chunks)?;
        self.put_cow(chunk, promoted).await?;
        let filled = match self.state_mut()?.commit(index, chunk) {
            Ok(filled) => filled,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Some(area) = filled {
            let terminator = self.state_mut()?.terminator_chunk()?;
            let zeros = buffer(self.chunk_size.len())?;
            self.put_cow(terminator, &zeros).await?;
            self.barrier().await?;
            let metadata = self.state_mut()?.buffer.clone();
            self.put_cow(area, &metadata).await?;
            self.state_mut()?.advance_area();
        }
        Ok(())
    }

    async fn write(&mut self, position: u64, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(Layer::<O, C>::poisoned());
        }
        let origin_bytes = self.origin_bytes;
        if position >= origin_bytes {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let chunk_bytes = self.chunk_bytes();
        let index = position / chunk_bytes;
        let within = usize::try_from(position % chunk_bytes)
            .map_err(|_| io::Error::other("position exceeds usize"))?;
        let count = usize::try_from(
            (origin_bytes - position)
                .min(input.len() as u64)
                .min(chunk_bytes - within as u64),
        )
        .map_err(|_| io::Error::other("write length exceeds usize"))?;
        self.write_chunk(index, within, &input[..count]).await?;
        Ok(count)
    }
}

impl<O, C: AsyncWrite + AsyncSeek + SyncData + Unpin> Core<O, C> {
    async fn flush(&mut self) -> io::Result<()> {
        let chunk_size = self.chunk_size;
        flush_cow(&mut self.cow, &mut self.state, &mut self.failed, chunk_size).await
    }
}

impl<O, C> Core<O, C>
where
    O: AsyncWrite + AsyncSeek + SyncData + Unpin,
    C: AsyncRead + AsyncWrite + AsyncSeek + SyncData + Unpin,
{
    async fn merge(&mut self) -> io::Result<()> {
        self.flush().await?;
        self.cow.sync_data().await?;

        let plan: Vec<_> = self.state_mut()?.exceptions().collect();
        let chunk_size = self.chunk_size;
        let chunk_bytes = chunk_size.bytes();
        let origin_bytes = self.origin_bytes;
        let origin_chunks = origin_bytes.div_ceil(chunk_bytes);
        if plan.iter().any(|(origin, _)| *origin >= origin_chunks) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the store holds an exception outside the origin it is merged into",
            ));
        }

        let mut chunk = buffer(self.chunk_size.len())?;
        for &(origin, cow) in &plan {
            let cow_offset = chunk_size.offset(cow)?;
            self.cow.seek(io::SeekFrom::Start(cow_offset)).await?;
            self.cow.read_exact(&mut chunk).await?;

            let origin_offset = chunk_size.offset(origin)?;
            let valid = usize::try_from((origin_bytes - origin_offset).min(chunk_bytes))
                .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
            self.origin.seek(io::SeekFrom::Start(origin_offset)).await?;
            self.origin.write_all(&chunk[..valid]).await?;
        }

        self.origin.flush().await?;
        self.origin.sync_data().await?;

        let per_area = chunk_bytes / State::EXCEPTION_LEN as u64;
        let areas = u64::try_from(plan.len())
            .unwrap_or(u64::MAX)
            .div_ceil(per_area)
            .max(1);
        chunk.fill(0);
        let retired = async {
            for area in (0..areas).rev() {
                let metadata = self.state_mut()?.metadata_chunk(area)?;
                let position = chunk_size.offset(metadata)?;
                self.cow.seek(io::SeekFrom::Start(position)).await?;
                self.cow.write_all(&chunk).await?;
            }
            self.cow.flush().await?;
            self.cow.sync_data().await
        }
        .await;
        if let Err(error) = retired {
            return Err(self.fatal(error));
        }
        self.state_mut()?.clear();
        Ok(())
    }
}

impl<O, C> Layer<O, C> {
    fn take_core(&mut self) -> io::Result<Core<O, C>> {
        self.ready()?;
        Ok(Core {
            origin: self.origin.take().ok_or_else(busy)?,
            cow: self.cow.take().ok_or_else(busy)?,
            origin_bytes: self.origin_bytes,
            cow_bytes: self.cow_bytes,
            chunk_size: self.chunk_size,
            state: self.state.take().ok_or_else(busy)?,
            failed: self.failed,
        })
    }

    fn restore(&mut self, core: Core<O, C>) {
        self.origin = Some(core.origin);
        self.cow = Some(core.cow);
        self.origin_bytes = core.origin_bytes;
        self.cow_bytes = core.cow_bytes;
        self.chunk_size = core.chunk_size;
        self.state = Some(core.state);
        self.failed = core.failed;
    }

    fn finish_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Output>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Err(busy()));
        };
        let operation = match pending {
            Pending::Read(operation)
            | Pending::Flush(operation)
            | Pending::Merge(operation)
            | Pending::Write { operation, .. } => operation,
        };
        match operation.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((core, result)) => {
                self.pending = None;
                self.restore(core);
                Poll::Ready(result)
            }
        }
    }
}

impl<O, C> Geometry for Layer<O, C> {
    fn block_size(&self) -> io::Result<std::num::NonZeroU32> {
        Ok(self.block_size)
    }

    fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
        Box::pin(std::future::ready(
            self.ready()
                .map(|()| self.origin_bytes / u64::from(self.block_size.get())),
        ))
    }
}

impl<O, C> AsyncRead for Layer<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    C: AsyncRead + AsyncSeek + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if matches!(
            self.pending,
            Some(Pending::Write { .. } | Pending::Flush(_) | Pending::Merge(_))
        ) {
            return Poll::Ready(Err(busy()));
        }
        if self.pending.is_none() {
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut core = match self.take_core() {
                Ok(core) => core,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let position = self.position;
            let maximum = output.remaining();
            self.pending = Some(Pending::Read(Box::pin(async move {
                let result = core.read(position, maximum).await.map(Output::Read);
                (core, result)
            })));
        }
        match self.finish_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(Output::Read(bytes))) => {
                if bytes.len() > output.remaining() {
                    return Poll::Ready(Err(busy()));
                }
                output.put_slice(&bytes);
                self.position += bytes.len() as u64;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(busy())),
        }
    }
}

impl<O, C> AsyncWrite for Layer<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    C: AsyncRead + AsyncWrite + AsyncSeek + SyncData + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(
            self.pending,
            Some(Pending::Read(_) | Pending::Flush(_) | Pending::Merge(_))
        ) {
            return Poll::Ready(Err(busy()));
        }
        if let Some(Pending::Write {
            input: expected, ..
        }) = self.pending.as_ref()
        {
            if !input.starts_with(expected) {
                return Poll::Ready(Err(busy()));
            }
        }
        if self.pending.is_none() {
            let copied = input[..input.len().min(64 * 1024)].to_vec();
            let key = copied.clone();
            let mut core = match self.take_core() {
                Ok(core) => core,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let position = self.position;
            self.pending = Some(Pending::Write {
                input: key,
                operation: Box::pin(async move {
                    let result = core.write(position, &copied).await.map(Output::Write);
                    (core, result)
                }),
            });
        }
        match self.finish_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(Output::Write(count))) => {
                self.position += count as u64;
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(busy())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(
            self.pending,
            Some(Pending::Read(_) | Pending::Write { .. } | Pending::Merge(_))
        ) {
            return Poll::Ready(Err(busy()));
        }
        if self.pending.is_none() {
            let mut core = match self.take_core() {
                Ok(core) => core,
                Err(error) => return Poll::Ready(Err(error)),
            };
            self.pending = Some(Pending::Flush(Box::pin(async move {
                let result = core.flush().await.map(|()| Output::Flush);
                (core, result)
            })));
        }
        match self.finish_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Output::Flush)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(busy())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl<O, C> AsyncSeek for Layer<O, C>
where
    O: Unpin,
    C: Unpin,
{
    fn start_seek(self: Pin<&mut Self>, seek: io::SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.pending.is_some() {
            return Err(busy());
        }
        this.ready()?;
        let next = match seek {
            io::SeekFrom::Start(position) => i128::from(position),
            io::SeekFrom::Current(delta) => i128::from(this.position) + i128::from(delta),
            io::SeekFrom::End(delta) => i128::from(this.origin_bytes) + i128::from(delta),
        };
        this.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before the start of a layer",
            )
        })?;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        if this.pending.is_some() {
            Poll::Ready(Err(busy()))
        } else {
            Poll::Ready(this.ready().map(|()| this.position))
        }
    }
}

impl<O, C> SyncData for Layer<O, C>
where
    C: AsyncWrite + AsyncSeek + SyncData + Unpin + Send,
{
    fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        let chunk_size = self.chunk_size;
        let Self {
            cow, state, failed, ..
        } = self;
        Box::pin(async move {
            let cow = cow.as_mut().ok_or_else(busy)?;
            let state = state.as_mut().ok_or_else(busy)?;
            flush_cow(cow, state, failed, chunk_size).await?;
            let result = cow.sync_data().await;
            if let Err(error) = result {
                *failed = true;
                Err(error)
            } else {
                Ok(())
            }
        })
    }
}
