// SPDX-License-Identifier: Apache-2.0

use std::io;

use devmap_core::traits::tokio::Geometry;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::superblock::{Formatter, Unverified};
use crate::traits::tokio::Format;
use crate::tree::TreeWriter;

impl<D, H> Format<D, H> for Formatter
where
    D: AsyncRead + Geometry + Unpin + Send,
    H: AsyncWrite + AsyncSeek + Geometry + Unpin + Send,
{
    async fn format(self, mut data: D, mut hashes: H) -> io::Result<Box<[u8]>> {
        let data_block_size = data.block_size()?;
        let data_size = data
            .count()
            .await?
            .checked_mul(u64::from(data_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "data geometry overflows"))?;
        let output_block_size = hashes.block_size()?;
        let superblock = self.superblock(data_size, data_block_size, output_block_size)?;
        hashes.seek(io::SeekFrom::Start(0)).await?;

        let encoded = Unverified::from(&superblock);
        let padding =
            u64::from(superblock.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, superblock)?;
        tree.output_mut().write_all(encoded.as_ref()).await?;
        tokio::io::copy(&mut tokio::io::repeat(0).take(padding), tree.output_mut()).await?;
        let copied = tokio::io::copy(&mut (&mut data).take(data_size), &mut tree).await?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush().await?;
        Ok(Box::from(tree.digest()?))
    }
}
