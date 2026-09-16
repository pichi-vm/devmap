// SPDX-License-Identifier: Apache-2.0

use std::io;

use devmap_core::traits::tokio::{Geometry, SyncData};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::superblock::Unverified;
use crate::traits::tokio::Format;
use crate::tree::TreeWriter;
use crate::{Hashes, Scheme, Shape, layout::Layout};

impl<D, H> Format<D, H> for Scheme
where
    D: AsyncRead + Geometry + Unpin + Send,
    H: AsyncWrite + AsyncSeek + Geometry + SyncData + Unpin + Send,
{
    async fn format(
        self,
        mut data: D,
        hashes: H,
        uuid: [u8; 16],
    ) -> io::Result<(Hashes<H>, Box<[u8]>)> {
        let data_block_size = data.block_size()?;
        let data_blocks = std::num::NonZeroU64::new(data.count().await?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "verity data is empty"))?;
        let shape = Shape::new(data_blocks)
            .with_data_block_size(data_block_size.try_into()?)
            .with_hash_block_size(hashes.block_size()?.try_into()?);
        let layout = Layout::new(&self, shape)?;
        let encoded = Unverified::try_from((&layout, uuid))?;
        let data_size = layout.data_size as u64;
        let padding = u64::from(layout.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, layout)?;
        tree.output_mut().seek(io::SeekFrom::Start(0)).await?;
        tree.output_mut().write_all(encoded.as_ref()).await?;
        tokio::io::copy(&mut tokio::io::repeat(0).take(padding), tree.output_mut()).await?;
        let copied = tokio::io::copy(&mut (&mut data).take(data_size), &mut tree).await?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush().await?;
        let (mut hashes, layout, root) = tree.finish()?;
        hashes.sync_data().await?;
        Ok((Hashes::new(hashes, uuid, layout), root))
    }
}
