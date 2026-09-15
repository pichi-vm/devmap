// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

use super::Hashes;
use crate::superblock::Unverified;
use crate::traits::std::OpenHashes;

impl<H: Read + Seek> OpenHashes<H> for Hashes<H> {
    fn open(mut storage: H) -> io::Result<Self> {
        storage.seek(SeekFrom::Start(0))?;
        let mut encoded = Unverified::default();
        storage.read_exact(encoded.as_mut())?;
        let (uuid, parameters) = encoded.decode()?;
        Ok(Self::new(storage, uuid, parameters))
    }
}

impl<H: devmap_core::traits::std::SyncData> devmap_core::traits::std::SyncData for Hashes<H> {
    fn sync_data(&mut self) -> io::Result<()> {
        self.inner.sync_data()
    }
}
