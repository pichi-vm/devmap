// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::{AsyncSyncData, Layer};

use super::Merge;

async fn run<O, C>(mut layer: Layer<O, C>) -> io::Result<(O, C)>
where
    O: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
    C: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
{
    AsyncSyncData::sync_data(&mut layer).await?;
    let plan: Vec<_> = layer.loaded()?.exceptions().collect();
    let chunk_bytes = layer.chunk_bytes()?;
    let origin_chunks = layer.origin_bytes.div_ceil(chunk_bytes);
    if plan.iter().any(|(origin, _)| *origin >= origin_chunks) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exception lies outside origin",
        ));
    }
    let mut chunk = vec![0; layer.chunk_usize()?];
    for (origin, cow) in &plan {
        layer
            .cow_mut()?
            .seek(io::SeekFrom::Start(cow * chunk_bytes))
            .await?;
        layer.cow_mut()?.read_exact(&mut chunk).await?;
        let position = origin * chunk_bytes;
        let valid = usize::try_from((layer.origin_bytes - position).min(chunk_bytes))
            .map_err(|_| io::Error::other("origin chunk length exceeds usize"))?;
        layer
            .origin_mut()?
            .seek(io::SeekFrom::Start(position))
            .await?;
        layer.origin_mut()?.write_all(&chunk[..valid]).await?;
    }
    layer.origin_mut()?.flush().await?;
    layer.origin_mut()?.sync_data().await?;

    let per_area = chunk_bytes / 16;
    let areas = u64::try_from(plan.len())
        .unwrap_or(u64::MAX)
        .div_ceil(per_area)
        .max(1);
    let zeros = vec![0; layer.chunk_usize()?];
    for area in (0..areas).rev() {
        let metadata = layer.loaded()?.metadata_chunk(area)?;
        layer
            .cow_mut()?
            .seek(io::SeekFrom::Start(metadata * chunk_bytes))
            .await?;
        layer.cow_mut()?.write_all(&zeros).await?;
    }
    layer.cow_mut()?.flush().await?;
    layer.cow_mut()?.sync_data().await?;
    layer.loaded()?.clear();
    layer.into_parts()
}

impl<O, C> Future for Merge<O, C>
where
    O: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
    C: AsyncRead + AsyncWrite + AsyncSeek + AsyncSyncData + Unpin + Send + 'static,
{
    type Output = io::Result<(O, C)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.pending.is_none() {
            let Some(layer) = self.layer.take() else {
                return Poll::Ready(Err(Self::finished()));
            };
            self.pending = Some(Box::pin(run(layer)));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(Err(Self::finished()));
        };
        match pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                Poll::Ready(result)
            }
        }
    }
}
