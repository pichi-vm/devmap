// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use devmap_core::traits::std::Geometry;

use crate::superblock::{Formatter, Unverified};
use crate::traits::std::Format;
use crate::tree::TreeWriter;

impl<D, H> Format<D, H> for Formatter
where
    D: Read + Geometry,
    H: Write + Seek + Geometry,
{
    fn format(self, mut data: D, mut hashes: H) -> io::Result<Box<[u8]>> {
        let data_block_size = data.block_size()?;
        let data_size = data
            .count()?
            .checked_mul(u64::from(data_block_size.get()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "data geometry overflows"))?;
        let output_block_size = hashes.block_size()?;
        let superblock = self.superblock(data_size, data_block_size, output_block_size)?;
        hashes.seek(SeekFrom::Start(0))?;

        let encoded = Unverified::from(&superblock);
        let padding =
            u64::from(superblock.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, superblock)?;
        tree.output_mut().write_all(encoded.as_ref())?;
        io::copy(&mut io::repeat(0).take(padding), tree.output_mut())?;
        let copied = io::copy(&mut data.by_ref().take(data_size), &mut tree)?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush()?;
        Ok(Box::from(tree.digest()?))
    }
}
