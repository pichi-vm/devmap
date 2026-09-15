// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sha2")]

use devmap_verity::{
    Parameters,
    traits::std::{Format as _, Geometry, SyncData},
};
use std::{
    io::{self, Cursor, Seek, Write},
    num::{NonZeroU32, NonZeroU64},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Write,
    Seek,
    Flush,
    Sync,
}

// Deliberately has no Read implementation: formatting must not reopen its output.
#[derive(Default)]
struct Output {
    bytes: Cursor<Vec<u8>>,
    flushes: usize,
    syncs: usize,
    failure: Option<Failure>,
    #[cfg(feature = "tokio")]
    paused: bool,
}

impl Output {
    fn check(&self, operation: Failure) -> io::Result<()> {
        if self.failure == Some(operation) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected output failure",
            ));
        }
        Ok(())
    }
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check(Failure::Write)?;
        self.bytes.write(&bytes[..bytes.len().min(31)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check(Failure::Flush)?;
        self.flushes += 1;
        Ok(())
    }
}

impl Seek for Output {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.check(Failure::Seek)?;
        self.bytes.seek(position)
    }
}

impl Geometry for Output {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }
    fn count(&mut self) -> io::Result<u64> {
        Ok(self.bytes.get_ref().len() as u64)
    }
}

impl SyncData for Output {
    fn sync_data(&mut self) -> io::Result<()> {
        self.check(Failure::Sync)?;
        self.syncs += 1;
        Ok(())
    }
}

#[test]
fn formatting_returns_metadata_without_reading_and_persists_only_on_request() {
    let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
    let (mut hashes, root) = parameters
        .clone()
        .format(Cursor::new(vec![7; 4096]), Output::default(), [3; 16])
        .unwrap();
    assert_eq!(hashes.parameters(), &parameters);
    assert_eq!(hashes.uuid(), [3; 16]);
    assert_eq!(root.len(), 32);
    hashes.sync_data().unwrap();
    let output = hashes.into_inner();
    assert!(output.flushes > 0);
    assert_eq!(output.syncs, 1);

    let reopened =
        <devmap_verity::Hashes<_> as devmap_verity::traits::std::OpenHashes<_>>::open(output.bytes)
            .unwrap();
    assert_eq!(reopened.parameters(), &parameters);
    assert_eq!(reopened.uuid(), [3; 16]);
}

#[test]
fn format_errors_never_return_a_completed_handle() {
    for failure in [Failure::Write, Failure::Seek, Failure::Flush] {
        let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
        let mut output = Output {
            failure: Some(failure),
            ..Output::default()
        };
        let error = parameters
            .format(Cursor::new(vec![0; 4096]), &mut output, [0; 16])
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(output.syncs, 0);
    }
}

#[test]
fn formatting_reports_insufficient_fixed_output_capacity() {
    let parameters = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(2).unwrap())
        .unwrap();
    let mut bytes = [0; 512];
    let error = parameters
        .format(
            Cursor::new(vec![0; 1024]),
            Cursor::new(bytes.as_mut_slice()),
            [0; 16],
        )
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
}

#[test]
fn header_limits_are_checked_before_any_output() {
    for builder in [
        Parameters::builder().salt(&[0; 257]),
        Parameters::builder().data_block_size(1 << 20).unwrap(),
        Parameters::builder().hash_block_size(1 << 20).unwrap(),
    ] {
        let parameters = builder.build(NonZeroU64::MIN).unwrap();
        let mut output = Output::default();
        let error = parameters
            .format(Cursor::new(Vec::<u8>::new()), &mut output, [0; 16])
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(output.bytes.get_ref().as_slice(), []);
        assert_eq!(output.flushes, 0);
    }
    let parameters = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(u64::MAX).unwrap())
        .unwrap();
    let mut output = Output::default();
    let error = parameters
        .format(Cursor::new(Vec::<u8>::new()), &mut output, [0; 16])
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(output.bytes.get_ref().as_slice(), []);
}

#[test]
fn persistence_failures_are_reported_by_the_returned_handle() {
    let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
    let output = Output {
        failure: Some(Failure::Sync),
        ..Output::default()
    };
    let (mut hashes, _) = parameters
        .format(Cursor::new(vec![0; 4096]), output, [0; 16])
        .unwrap();
    assert_eq!(
        hashes.sync_data().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let output = hashes.into_inner();
    assert!(output.flushes > 0);
    assert_eq!(output.syncs, 0);
}

#[cfg(feature = "tokio")]
mod asynchronous {
    use super::*;
    use devmap_verity::traits::tokio::{Format, Geometry, SyncData};
    use std::{
        future::{Future, poll_fn},
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncSeek, AsyncWrite};

    impl AsyncWrite for Output {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.paused = !self.paused;
            if self.paused {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Write::write(&mut *self, bytes))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Write::flush(&mut *self))
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    impl AsyncSeek for Output {
        fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
            Seek::seek(&mut *self, position)?;
            Ok(())
        }
        fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
            Poll::Ready(Ok(self.bytes.position()))
        }
    }

    impl Geometry for Output {
        fn block_size(&self) -> io::Result<NonZeroU32> {
            Ok(NonZeroU32::MIN)
        }
        fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(self.bytes.get_ref().len() as u64)))
        }
    }

    impl SyncData for Output {
        fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(std::future::ready(super::SyncData::sync_data(self)))
        }
    }

    #[tokio::test]
    async fn async_format_handles_short_pending_output_without_a_reread() {
        let parameters = Parameters::builder()
            .build(NonZeroU64::new(129).unwrap())
            .unwrap();
        let bytes = vec![7; 129 * 4096];
        let (mut hashes, root) = Format::format(
            parameters.clone(),
            Cursor::new(&bytes),
            Output::default(),
            [9; 16],
        )
        .await
        .unwrap();
        assert_eq!(hashes.parameters(), &parameters);
        assert_eq!(hashes.uuid(), [9; 16]);
        SyncData::sync_data(&mut hashes).await.unwrap();
        let output = hashes.into_inner();
        assert!(output.flushes > 0);
        assert_eq!(output.syncs, 1);
        let (expected, expected_root) = devmap_verity::traits::std::Format::format(
            parameters,
            Cursor::new(&bytes),
            Cursor::new(Vec::new()),
            [9; 16],
        )
        .unwrap();
        assert_eq!(root, expected_root);
        assert_eq!(
            output.bytes.into_inner(),
            expected.into_inner().into_inner()
        );
    }

    #[tokio::test]
    async fn async_output_failures_return_no_completed_handle() {
        for failure in [Failure::Write, Failure::Seek, Failure::Flush] {
            let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
            let output = Output {
                failure: Some(failure),
                ..Output::default()
            };
            let error = Format::format(parameters, Cursor::new(vec![0; 4096]), output, [0; 16])
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
        let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
        let output = Output {
            failure: Some(Failure::Sync),
            ..Output::default()
        };
        let (mut hashes, _) =
            Format::format(parameters, Cursor::new(vec![0; 4096]), output, [0; 16])
                .await
                .unwrap();
        assert_eq!(
            SyncData::sync_data(&mut hashes).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn cancelled_format_leaves_partial_output_that_can_be_reformatted() {
        let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
        let mut output = Output::default();
        {
            let mut operation = Box::pin(Format::format(
                parameters.clone(),
                Cursor::new(vec![0; 4096]),
                &mut output,
                [0; 16],
            ));
            let mut polls = 0;
            poll_fn(|cx| {
                assert!(operation.as_mut().poll(cx).is_pending());
                polls += 1;
                if polls == 2 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        assert_ne!(output.bytes.get_ref().as_slice(), []);
        assert_eq!(output.flushes, 0);
        let (hashes, _) = Format::format(parameters, Cursor::new(vec![7; 4096]), output, [1; 16])
            .await
            .unwrap();
        assert_eq!(hashes.uuid(), [1; 16]);
        assert!(hashes.into_inner().flushes > 0);
    }
}
