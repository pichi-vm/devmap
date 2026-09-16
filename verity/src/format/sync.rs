// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use devmap_core::traits::std::{Geometry, SyncData};

use crate::superblock::Unverified;
use crate::traits::std::Format;
use crate::tree::TreeWriter;
use crate::{Hashes, Scheme, Shape, layout::Layout};

impl<D, H> Format<D, H> for Scheme
where
    D: Read + Geometry,
    H: Write + Seek + Geometry + SyncData,
{
    fn format(self, mut data: D, hashes: H, uuid: [u8; 16]) -> io::Result<(Hashes<H>, Box<[u8]>)> {
        let data_block_size = data.block_size()?;
        let data_blocks = std::num::NonZeroU64::new(data.count()?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "verity data is empty"))?;
        let shape = Shape::new(data_blocks)
            .with_data_block_size(data_block_size.try_into()?)
            .with_hash_block_size(hashes.block_size()?.try_into()?);
        let layout = Layout::new(&self, shape)?;
        let encoded = Unverified::try_from((&layout, uuid))?;
        let data_size = layout.data_size as u64;
        let padding = u64::from(layout.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, layout)?;
        tree.output_mut().seek(SeekFrom::Start(0))?;
        tree.output_mut().write_all(encoded.as_ref())?;
        io::copy(&mut io::repeat(0).take(padding), tree.output_mut())?;
        let copied = io::copy(&mut data.by_ref().take(data_size), &mut tree)?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush()?;
        let (mut hashes, layout, root) = tree.finish()?;
        hashes.sync_data()?;
        Ok((Hashes::new(hashes, uuid, layout), root))
    }
}
