// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Cursor, ErrorKind, Seek as _, SeekFrom, Write as _},
    num::NonZero,
    pin::Pin,
    task::{Context, Poll},
};

use devmap_core::{BlockSize, Geometry};
use devmap_verity::{
    AsyncFormat, Format,
    header::{Algorithm, Constraint, HashType, Header, Salt},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

struct FragmentedCursor {
    inner: Cursor<Vec<u8>>,
    read_size: usize,
    write_size: usize,
    pending: bool,
    seek: Option<SeekFrom>,
}

impl FragmentedCursor {
    fn new(bytes: Vec<u8>, position: u64, read_size: usize, write_size: usize) -> Self {
        let mut inner = Cursor::new(bytes);
        inner.set_position(position);
        Self {
            inner,
            read_size,
            write_size,
            pending: true,
            seek: None,
        }
    }

    fn poll_pending(&mut self, cx: &Context<'_>) -> bool {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            true
        } else {
            self.pending = true;
            false
        }
    }

    fn position(&self) -> u64 {
        self.inner.position()
    }

    fn bytes(&self) -> &[u8] {
        self.inner.get_ref()
    }
}

impl AsyncRead for FragmentedCursor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_pending(cx) {
            return Poll::Pending;
        }

        let Ok(start) = usize::try_from(this.inner.position()) else {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidInput,
                "cursor position does not fit in usize",
            )));
        };
        let available = this.inner.get_ref().len().saturating_sub(start);
        let count = available.min(output.remaining()).min(this.read_size);
        output.put_slice(&this.inner.get_ref()[start..start + count]);
        this.inner.set_position((start + count) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FragmentedCursor {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.poll_pending(cx) {
            return Poll::Pending;
        }
        let count = input.len().min(this.write_size);
        Poll::Ready(this.inner.write(&input[..count]))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_pending(cx) {
            return Poll::Pending;
        }
        Poll::Ready(this.inner.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncSeek for FragmentedCursor {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.seek.is_some() {
            return Err(io::Error::other("seek already in progress"));
        }
        this.seek = Some(position);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        if this.poll_pending(cx) {
            return Poll::Pending;
        }
        Poll::Ready(match this.seek.take() {
            Some(position) => this.inner.seek(position),
            None => Ok(this.inner.position()),
        })
    }
}

fn header(blocks: u64) -> Header {
    Header {
        uuid: [0x5a; 16],
        hash_type: HashType::Normal,
        algorithm: Algorithm::Sha256,
        salt: Salt::new(&[1, 2, 3]).unwrap(),
        data: Geometry::<Constraint> {
            size: BlockSize::default(),
            count: NonZero::new(blocks).unwrap(),
        },
        hash: BlockSize::default(),
    }
}

#[tokio::test]
async fn fragmented_pending_io_matches_synchronous_formatting() {
    const BLOCKS: u64 = 300;
    const BLOCK_SIZE: usize = 4096;
    const DATA_SIZE: usize = 300 * BLOCK_SIZE;
    const PREFIX: &[u8] = b"prefix before verity metadata";

    let mut bytes: Vec<_> = (0_u8..251).cycle().take(DATA_SIZE).collect();
    bytes.extend_from_slice(b"input after the declared extent");
    let header = header(BLOCKS);
    let formatted_size = u64::from(header.hash.bytes().get()) + header.tree_size().unwrap();

    let mut sync_data = Cursor::new(bytes.clone());
    let mut sync_hash = Cursor::new(PREFIX.to_vec());
    sync_hash.set_position(PREFIX.len() as u64);
    let sync_root = Format::format(header, &mut sync_data, &mut sync_hash).unwrap();

    let mut async_data = FragmentedCursor::new(bytes, 0, 53, usize::MAX);
    let mut async_hash =
        FragmentedCursor::new(PREFIX.to_vec(), PREFIX.len() as u64, usize::MAX, 37);
    let async_root = AsyncFormat::format(header, &mut async_data, &mut async_hash)
        .await
        .unwrap();

    assert_eq!(async_root, sync_root);
    assert_eq!(async_hash.bytes(), sync_hash.get_ref());
    assert_eq!(async_data.position(), BLOCKS * 4096);
    assert_eq!(&async_hash.bytes()[..PREFIX.len()], PREFIX);
    assert_eq!(async_hash.position(), PREFIX.len() as u64 + formatted_size);
}

#[tokio::test]
async fn short_input_reports_unexpected_eof() {
    let mut data = FragmentedCursor::new(vec![0x5a; 4096], 0, 31, usize::MAX);
    let mut hash = FragmentedCursor::new(Vec::new(), 0, usize::MAX, 29);

    let error = AsyncFormat::format(header(2), &mut data, &mut hash)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn oversized_extent_is_rejected_before_writing() {
    let mut data = FragmentedCursor::new(Vec::new(), 0, 17, usize::MAX);
    let mut hash = FragmentedCursor::new(Vec::new(), 0, usize::MAX, 13);

    let error = AsyncFormat::format(header(u64::MAX), &mut data, &mut hash)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(hash.bytes(), []);
}
