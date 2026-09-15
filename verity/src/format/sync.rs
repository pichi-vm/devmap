// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom, Write};

use devmap_core::traits::std::Geometry;

use crate::superblock::Unverified;
use crate::traits::std::Format;
use crate::tree::TreeWriter;
use crate::{Hashes, Parameters};

impl<D, H> Format<D, H> for Parameters
where
    D: Read + Geometry,
    H: Write + Seek + Geometry,
{
    fn format(self, mut data: D, hashes: H, uuid: [u8; 16]) -> io::Result<(Hashes<H>, Box<[u8]>)> {
        let encoded = Unverified::try_from((&self, uuid))?;
        self.validate_format_geometry(data.block_size()?, hashes.block_size()?)?;
        let data_size = self.layout.data_size as u64;
        let padding = u64::from(self.hash_block_size().get()) - size_of::<Unverified>() as u64;
        let mut tree = TreeWriter::new(hashes, self)?;
        tree.output_mut().seek(SeekFrom::Start(0))?;
        tree.output_mut().write_all(encoded.as_ref())?;
        io::copy(&mut io::repeat(0).take(padding), tree.output_mut())?;
        let copied = io::copy(&mut data.by_ref().take(data_size), &mut tree)?;
        if copied != data_size {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        tree.flush()?;
        let (hashes, parameters, root) = tree.finish()?;
        Ok((Hashes::new(hashes, uuid, parameters), root))
    }
}
