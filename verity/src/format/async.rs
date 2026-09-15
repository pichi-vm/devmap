// SPDX-License-Identifier: Apache-2.0

use std::io;

use devmap_core::traits::tokio::Geometry;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

use crate::superblock::Unverified;
use crate::traits::tokio::Format;
use crate::tree::TreeWriter;
use crate::{Hashes, Parameters};

impl<D, H> Format<D, H> for Parameters
where
    D: AsyncRead + Geometry + Unpin + Send,
    H: AsyncWrite + AsyncSeek + Geometry + Unpin + Send,
{
    async fn format(
        self,
        mut data: D,
        hashes: H,
        uuid: [u8; 16],
    ) -> io::Result<(Hashes<H>, Box<[u8]>)> {
        let encoded = Unverified::try_from((&self, uuid))?;
        self.validate_format_geometry(data.block_size()?, hashes.block_size()?)?;
        let data_size = self.layout.data_size as u64;
        let padding = u64::from(self.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, self)?;
        tree.output_mut().seek(io::SeekFrom::Start(0)).await?;
        tree.output_mut().write_all(encoded.as_ref()).await?;
        tokio::io::copy(&mut tokio::io::repeat(0).take(padding), tree.output_mut()).await?;
        let copied = tokio::io::copy(&mut (&mut data).take(data_size), &mut tree).await?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush().await?;
        let (hashes, parameters, root) = tree.finish()?;
        Ok((Hashes::new(hashes, uuid, parameters), root))
    }
}
