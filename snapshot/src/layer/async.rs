// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};

use crate::{AsyncSyncData, ChunkSize};

use super::state::{State, buffer};
use super::{Layer, Load};

fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "another asynchronous layer operation is in progress",
    )
}

fn offset(index: u64, chunk_bytes: u64) -> io::Result<u64> {
    index
        .checked_mul(chunk_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "snapshot offset overflows"))
}

pub(super) struct Core<O, C> {
    origin: O,
    cow: C,
    origin_bytes: u64,
    cow_bytes: u64,
    chunk_size: Option<ChunkSize>,
    state: Option<State>,
    load: Load,
    fresh: bool,
}

pub(super) enum Output {
    Read(Vec<u8>),
    Write(usize),
    Flush,
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
}

impl<O, C> Core<O, C> {
    fn chunk_bytes(&self) -> io::Result<u64> {
        self.chunk_size
            .map(|size| size.bytes().get())
            .ok_or_else(|| io::Error::other("the snapshot chunk size is not loaded"))
    }

    fn chunk_usize(&self) -> io::Result<usize> {
        usize::try_from(self.chunk_bytes()?)
            .map_err(|_| io::Error::other("chunk size exceeds usize"))
    }

    fn cow_chunks(&self) -> io::Result<u64> {
        Ok(self.cow_bytes / self.chunk_bytes()?)
    }

    fn loaded(&mut self) -> io::Result<&mut State> {
        self.state
            .as_mut()
            .ok_or_else(|| io::Error::other("the exception store is not loaded"))
    }

    fn fatal(&mut self, error: io::Error) -> io::Error {
        self.load = Load::Failed;
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

async fn write_at<W: AsyncWrite + AsyncSeek + Unpin>(
    writer: &mut W,
    position: u64,
    bytes: &[u8],
) -> io::Result<()> {
    writer.seek(io::SeekFrom::Start(position)).await?;
    writer.write_all(bytes).await
}

impl<O, C: AsyncRead + AsyncSeek + Unpin> Core<O, C> {
    async fn load(&mut self) -> io::Result<()> {
        match self.load {
            Load::Ready => return Ok(()),
            Load::Failed => return Err(Layer::<O, C>::poisoned()),
            Load::Create => {
                self.state = Some(State::new(self.chunk_usize()?)?);
                self.load = Load::Ready;
                return Ok(());
            }
            Load::Open => {}
        }
        let mut header = [0; ChunkSize::HEADER_LEN];
        read_at(&mut self.cow, 0, &mut header).await?;
        let parsed_size = match ChunkSize::from_header(&header) {
            Ok(size) => size,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Err(error) = Layer::<O, C>::validate_cow(self.cow_bytes, parsed_size) {
            return Err(self.fatal(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        self.chunk_size = Some(parsed_size);
        let chunk_bytes = self.chunk_bytes()?;
        let allocation_size = self.chunk_usize()?;
        self.state = Some(State::new(allocation_size)?);
        let cow_chunks = self.cow_chunks()?;
        let mut area = 0;
        loop {
            let chunk = self.loaded()?.metadata_chunk(area)?;
            if chunk >= cow_chunks {
                return Err(self.fatal(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot metadata walk leaves the store",
                )));
            }
            let mut bytes = buffer(allocation_size)?;
            read_at(&mut self.cow, offset(chunk, chunk_bytes)?, &mut bytes).await?;
            self.loaded()?.buffer_mut().copy_from_slice(&bytes);
            match self.loaded()?.absorb_area(area, cow_chunks) {
                Ok(true) => break,
                Ok(false) => {
                    area = area.checked_add(1).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snapshot metadata area overflows",
                        )
                    })?;
                }
                Err(error) => return Err(self.fatal(error)),
            }
        }
        self.load = Load::Ready;
        Ok(())
    }
}

impl<O, C: AsyncWrite + AsyncSeek + AsyncSyncData + Unpin> Core<O, C> {
    async fn put_cow(&mut self, chunk: u64, bytes: &[u8]) -> io::Result<()> {
        let position = offset(chunk, self.chunk_bytes()?)?;
        let result = write_at(&mut self.cow, position, bytes).await;
        result.map_err(|error| self.fatal(error))
    }

    async fn barrier(&mut self) -> io::Result<()> {
        let result = self.cow.sync_data().await;
        result.map_err(|error| self.fatal(error))
    }

    async fn prepare(&mut self) -> io::Result<()> {
        if !self.fresh {
            return Ok(());
        }
        let area = self.loaded()?.current_metadata_chunk()?;
        let zeros = buffer(self.chunk_usize()?)?;
        self.put_cow(area, &zeros).await?;
        self.barrier().await?;
        let mut header = zeros;
        let encoded = self
            .chunk_size
            .ok_or_else(|| io::Error::other("snapshot chunk size is not loaded"))?
            .header();
        header[..encoded.len()].copy_from_slice(&encoded);
        self.put_cow(0, &header).await?;
        self.fresh = false;
        Ok(())
    }
}

impl<O: AsyncRead + AsyncSeek + Unpin, C: AsyncRead + AsyncSeek + Unpin> Core<O, C> {
    async fn read_prefix(&mut self, index: u64, bytes: &mut [u8]) -> io::Result<()> {
        let chunk_bytes = self.chunk_bytes()?;
        let source = self.loaded()?.lookup(index);
        match source {
            Some(chunk) => read_at(&mut self.cow, offset(chunk, chunk_bytes)?, bytes).await,
            None => read_at(&mut self.origin, offset(index, chunk_bytes)?, bytes).await,
        }
    }

    async fn read(&mut self, position: u64, maximum: usize) -> io::Result<Vec<u8>> {
        if maximum == 0 || position >= self.origin_bytes {
            return Ok(Vec::new());
        }
        self.load().await?;
        let chunk_bytes = self.chunk_bytes()?;
        let index = position / chunk_bytes;
        let within = usize::try_from(position % chunk_bytes)
            .map_err(|_| io::Error::other("position exceeds usize"))?;
        let count = usize::try_from(
            (self.origin_bytes - position)
                .min(maximum as u64)
                .min(chunk_bytes - within as u64),
        )
        .map_err(|_| io::Error::other("read length exceeds usize"))?;
        let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
            .map_err(|_| io::Error::other("chunk length exceeds usize"))?;
        let mut chunk = buffer(self.chunk_usize()?)?;
        self.read_prefix(index, &mut chunk[..valid]).await?;
        Ok(chunk[within..within + count].to_vec())
    }
}

impl<O, C> Core<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin,
    C: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin,
{
    async fn write_full(&mut self, index: u64, bytes: &[u8]) -> io::Result<()> {
        self.prepare().await?;
        let cow_chunks = self.cow_chunks()?;
        let (chunk, fresh) = self.loaded()?.plan(index, cow_chunks)?;
        self.put_cow(chunk, bytes).await?;
        let filled = match self.loaded()?.commit(index, chunk, fresh) {
            Ok(filled) => filled,
            Err(error) => return Err(self.fatal(error)),
        };
        if let Some(area) = filled {
            let terminator = self.loaded()?.terminator_chunk()?;
            let zeros = buffer(self.chunk_usize()?)?;
            self.put_cow(terminator, &zeros).await?;
            self.barrier().await?;
            let metadata = self.loaded()?.buffer().to_vec();
            self.put_cow(area, &metadata).await?;
            self.loaded()?.advance_area();
        }
        Ok(())
    }

    async fn write(&mut self, position: u64, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if position >= self.origin_bytes {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.load().await?;
        let chunk_bytes = self.chunk_bytes()?;
        let index = position / chunk_bytes;
        let within = usize::try_from(position % chunk_bytes)
            .map_err(|_| io::Error::other("position exceeds usize"))?;
        let count = usize::try_from(
            (self.origin_bytes - position)
                .min(input.len() as u64)
                .min(chunk_bytes - within as u64),
        )
        .map_err(|_| io::Error::other("write length exceeds usize"))?;
        let mut chunk = buffer(self.chunk_usize()?)?;
        if within != 0 || count != chunk.len() {
            let valid = usize::try_from((self.origin_bytes - index * chunk_bytes).min(chunk_bytes))
                .map_err(|_| io::Error::other("chunk length exceeds usize"))?;
            self.read_prefix(index, &mut chunk[..valid]).await?;
        }
        chunk[within..within + count].copy_from_slice(&input[..count]);
        self.write_full(index, &chunk).await?;
        Ok(count)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.load().await?;
        self.prepare().await?;
        if self.loaded()?.is_dirty() {
            self.barrier().await?;
            let chunk = self.loaded()?.current_metadata_chunk()?;
            let metadata = self.loaded()?.buffer().to_vec();
            self.put_cow(chunk, &metadata).await?;
            self.loaded()?.published();
        }
        let result = self.cow.flush().await;
        result.map_err(|error| self.fatal(error))
    }
}

impl<O, C> Layer<O, C> {
    fn take_core(&mut self) -> io::Result<Core<O, C>> {
        Ok(Core {
            origin: self.origin.take().ok_or_else(busy)?,
            cow: self.cow.take().ok_or_else(busy)?,
            origin_bytes: self.origin_bytes,
            cow_bytes: self.cow_bytes,
            chunk_size: self.chunk_size,
            state: self.state.take(),
            load: self.load,
            fresh: self.fresh,
        })
    }

    fn restore(&mut self, core: Core<O, C>) {
        self.origin = Some(core.origin);
        self.cow = Some(core.cow);
        self.chunk_size = core.chunk_size;
        self.state = core.state;
        self.load = core.load;
        self.fresh = core.fresh;
    }

    fn finish_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Output>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Err(busy()));
        };
        let operation = match pending {
            Pending::Read(operation)
            | Pending::Flush(operation)
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
            Some(Pending::Write { .. } | Pending::Flush(_))
        ) {
            return Poll::Ready(Err(busy()));
        }
        if self.pending.is_none() {
            if output.remaining() == 0 || self.position >= self.origin_bytes {
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
    C: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if matches!(self.pending, Some(Pending::Read(_) | Pending::Flush(_))) {
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
        if matches!(self.pending, Some(Pending::Read(_) | Pending::Write { .. })) {
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

impl<O: Unpin, C: Unpin> AsyncSeek for Layer<O, C> {
    fn start_seek(self: Pin<&mut Self>, seek: io::SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.pending.is_some() {
            return Err(busy());
        }
        let next = match seek {
            io::SeekFrom::Start(position) => i128::from(position),
            io::SeekFrom::Current(delta) => i128::from(this.position) + i128::from(delta),
            io::SeekFrom::End(delta) => i128::from(this.origin_bytes) + i128::from(delta),
        };
        this.position = u64::try_from(next).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot seek before layer start",
            )
        })?;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.get_mut().position))
    }
}

impl<O, C> AsyncSyncData for Layer<O, C>
where
    O: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    C: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
{
    async fn sync_data(&mut self) -> io::Result<()> {
        AsyncWriteExt::flush(self).await?;
        self.cow_mut()?.sync_data().await
    }
}
