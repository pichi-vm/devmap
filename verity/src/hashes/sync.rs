// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read, Seek, SeekFrom};

use super::Hashes;
use crate::superblock::{Header, Unverified};
use crate::traits::std::OpenHashes;

impl<H: Read + Seek> OpenHashes<H> for Hashes<H> {
    fn open(mut storage: H) -> io::Result<Self> {
        storage.seek(SeekFrom::Start(0))?;
        let mut encoded = Unverified::default();
        storage.read_exact(encoded.as_mut())?;
        let header = Header::try_from(&encoded)?;
        Ok(Self::new(storage, header))
    }
}
