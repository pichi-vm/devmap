// SPDX-License-Identifier: Apache-2.0

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _};

use super::Hashes;
use crate::superblock::{Header, Unverified};
use crate::traits::tokio::OpenHashes;

impl<H: AsyncRead + AsyncSeek + Unpin + Send> OpenHashes<H> for Hashes<H> {
    async fn open(mut storage: H) -> io::Result<Self> {
        storage.seek(io::SeekFrom::Start(0)).await?;
        let mut encoded = Unverified::default();
        storage.read_exact(encoded.as_mut()).await?;
        let header = Header::try_from(&encoded)?;
        Ok(Self::new(storage, header))
    }
}
