// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sha2")]

use devmap_verity::{
    Scheme, Shape,
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
    #[cfg(feature = "tokio")]
    stall_sync: bool,
    #[cfg(feature = "tokio")]
    persisting: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
        Ok(NonZeroU32::new(4096).unwrap())
    }
    fn count(&mut self) -> io::Result<u64> {
        Ok(self.bytes.get_ref().len() as u64 / 4096)
    }
}

impl SyncData for Output {
    fn sync_data(&mut self) -> io::Result<()> {
        self.check(Failure::Sync)?;
        assert!(self.flushes > 0);
        self.syncs += 1;
        Ok(())
    }
}

fn input(bytes: Vec<u8>) -> devmap_core::Scaled<Cursor<Vec<u8>>> {
    devmap_core::traits::std::Scale::scale_to(Cursor::new(bytes), NonZeroU32::new(4096).unwrap())
        .unwrap()
}

#[test]
fn formatting_returns_metadata_without_reading_and_persists_before_returning() {
    let scheme = Scheme::default();
    let (hashes, root) = scheme
        .format(input(vec![7; 4096]), Output::default(), [3; 16])
        .unwrap();
    assert_eq!(hashes.scheme(), scheme);
    assert_eq!(hashes.shape(), Shape::new(NonZeroU64::MIN));
    assert_eq!(hashes.uuid(), [3; 16]);
    assert_eq!(root.len(), 32);
    let output = hashes.into_inner();
    assert!(output.flushes > 0);
    assert_eq!(output.syncs, 1);
    let reopened =
        <devmap_verity::Hashes<_> as devmap_verity::traits::std::OpenHashes<_>>::open(output.bytes)
            .unwrap();
    assert_eq!(reopened.scheme(), scheme);
    assert_eq!(reopened.shape(), Shape::new(NonZeroU64::MIN));
}

#[test]
fn format_errors_including_persistence_never_return_a_completed_handle() {
    for failure in [Failure::Write, Failure::Seek, Failure::Flush, Failure::Sync] {
        let mut output = Output {
            failure: Some(failure),
            ..Output::default()
        };
        let error = Scheme::default()
            .format(input(vec![0; 4096]), &mut output, [0; 16])
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(output.syncs, 0);
        if failure == Failure::Sync {
            assert!(output.flushes > 0);
        }
    }
}

#[test]
fn formatting_reports_insufficient_fixed_output_capacity() {
    let mut bytes = [0; 4096];
    let output = devmap_core::traits::std::Scale::scale_to(
        Cursor::new(bytes.as_mut_slice()),
        NonZeroU32::new(4096).unwrap(),
    )
    .unwrap();
    let error = Scheme::default()
        .format(input(vec![0; 8192]), output, [0; 16])
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
}

#[test]
fn header_geometry_limits_are_checked_before_any_output() {
    struct GeometryOnly {
        block: NonZeroU32,
        count: u64,
    }
    impl io::Read for GeometryOnly {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("invalid geometry must fail before reading")
        }
    }
    impl Geometry for GeometryOnly {
        fn block_size(&self) -> io::Result<NonZeroU32> {
            Ok(self.block)
        }
        fn count(&mut self) -> io::Result<u64> {
            Ok(self.count)
        }
    }
    for (block, count) in [(1, 1), (513, 1), (1 << 20, 1), (512, u64::MAX), (512, 0)] {
        let mut output = Output::default();
        let data = GeometryOnly {
            block: NonZeroU32::new(block).unwrap(),
            count,
        };
        let error = Scheme::default()
            .format(data, &mut output, [0; 16])
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(output.bytes.get_ref().as_slice(), []);
        assert_eq!(output.flushes, 0);
        assert_eq!(output.syncs, 0);
    }
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
            Ok(NonZeroU32::new(4096).unwrap())
        }
        fn count(&mut self) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(
                self.bytes.get_ref().len() as u64 / 4096
            )))
        }
    }

    impl SyncData for Output {
        fn sync_data(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(async move {
                if self.stall_sync {
                    self.persisting
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    std::future::pending::<()>().await;
                }
                super::SyncData::sync_data(self)
            })
        }
    }

    #[tokio::test]
    async fn async_format_handles_short_pending_output_and_persists() {
        let bytes = vec![7; 129 * 4096];
        let (hashes, root) = Format::format(
            Scheme::default(),
            input(bytes.clone()),
            Output::default(),
            [9; 16],
        )
        .await
        .unwrap();
        assert_eq!(hashes.shape(), Shape::new(NonZeroU64::new(129).unwrap()));
        assert_eq!(hashes.uuid(), [9; 16]);
        let output = hashes.into_inner();
        assert!(output.flushes > 0);
        assert_eq!(output.syncs, 1);
        let (expected, expected_root) = devmap_verity::traits::std::Format::format(
            Scheme::default(),
            input(bytes),
            Output::default(),
            [9; 16],
        )
        .unwrap();
        assert_eq!(root, expected_root);
        assert_eq!(
            output.bytes.into_inner(),
            expected.into_inner().bytes.into_inner()
        );
    }

    #[tokio::test]
    async fn async_output_and_persistence_failures_return_no_handle() {
        for failure in [Failure::Write, Failure::Seek, Failure::Flush, Failure::Sync] {
            let mut output = Output {
                failure: Some(failure),
                ..Output::default()
            };
            let error = Format::format(
                Scheme::default(),
                input(vec![0; 4096]),
                &mut output,
                [0; 16],
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(output.syncs, 0);
        }
    }

    #[tokio::test]
    async fn cancelled_format_can_be_restarted_without_claiming_persistence() {
        let mut output = Output::default();
        {
            let mut operation = Box::pin(Format::format(
                Scheme::default(),
                input(vec![0; 4096]),
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
        assert_eq!(output.syncs, 0);
        let (hashes, _) = Format::format(Scheme::default(), input(vec![7; 4096]), output, [1; 16])
            .await
            .unwrap();
        assert_eq!(hashes.uuid(), [1; 16]);
        assert_eq!(hashes.into_inner().syncs, 1);
    }
    #[tokio::test]
    async fn cancellation_during_persistence_returns_no_completed_handle() {
        let mut output = Output {
            stall_sync: true,
            ..Output::default()
        };
        let persisting = output.persisting.clone();
        {
            let mut operation = Box::pin(Format::format(
                Scheme::default(),
                input(vec![0; 4096]),
                &mut output,
                [0; 16],
            ));
            poll_fn(|cx| {
                assert!(operation.as_mut().poll(cx).is_pending());
                if persisting.load(std::sync::atomic::Ordering::Relaxed) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        assert!(output.flushes > 0);
        assert_eq!(output.syncs, 0);
        output.stall_sync = false;
        let (hashes, _) = Format::format(Scheme::default(), input(vec![0; 4096]), output, [0; 16])
            .await
            .unwrap();
        assert_eq!(hashes.into_inner().syncs, 1);
    }
}
