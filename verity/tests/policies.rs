// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sha2")]

use devmap_core::parse::DevId;
use devmap_verity::traits::std::{Format as _, Geometry, Open as _, OpenHashes as _, Scale as _};
use devmap_verity::{
    CorruptionPolicy, Fec, HashType, Hashes, IoErrorPolicy, KeyDescription, Options, Scheme,
};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

fn image(bytes: &[u8], hash_type: HashType) -> (Vec<u8>, Box<[u8]>) {
    let size = NonZeroU32::new(512).unwrap();
    let input = Cursor::new(bytes).scale_to(size).unwrap();
    let output = Cursor::new(Vec::new()).scale_to(size).unwrap();
    let (hashes, root) = Scheme::default()
        .with_hash_type(hash_type)
        .with_salt(&[7; 17])
        .unwrap()
        .format(input, output, [0; 16])
        .unwrap();
    (hashes.into_inner().into_inner().into_inner(), root)
}

struct Data {
    bytes: Arc<Mutex<Vec<u8>>>,
    position: usize,
    reads: Arc<AtomicUsize>,
    error: Arc<Mutex<Option<io::ErrorKind>>>,
}
impl Data {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Arc::new(Mutex::new(bytes)),
            position: 0,
            reads: Arc::default(),
            error: Arc::default(),
        }
    }
}
impl Read for Data {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = *self.error.lock().unwrap() {
            return Err(error.into());
        }
        let bytes = self.bytes.lock().unwrap();
        let start = self.position.min(bytes.len());
        let count = output.len().min(bytes.len() - start);
        output[..count].copy_from_slice(&bytes[start..start + count]);
        self.position += count;
        Ok(count)
    }
}
impl Seek for Data {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let value = match position {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => self.position as i128 + i128::from(n),
            SeekFrom::End(n) => self.bytes.lock().unwrap().len() as i128 + i128::from(n),
        };
        self.position = usize::try_from(value).map_err(|_| io::ErrorKind::InvalidInput)?;
        Ok(self.position as u64)
    }
}
impl Geometry for Data {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }
    fn count(&mut self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap().len() as u64)
    }
}

#[test]
fn authenticated_zero_blocks_need_no_data_read_but_still_need_a_valid_root() {
    for hash_type in [HashType::Normal, HashType::ChromeOs] {
        for blocks in [1, 17] {
            let (storage, root) = image(&vec![0; blocks * 512], hash_type);
            for bad_root in [false, true] {
                let mut root = root.clone();
                if bad_root {
                    root[0] ^= 1;
                }
                let data = Data::new(if bad_root && blocks == 1 {
                    vec![0; 512]
                } else {
                    vec![99; blocks * 512]
                });
                if !bad_root || blocks > 1 {
                    *data.error.lock().unwrap() = Some(io::ErrorKind::PermissionDenied);
                }
                let reads = data.reads.clone();
                let mut volume = Options::default()
                    .with_ignore_zero_blocks(true)
                    .open(
                        data,
                        Hashes::open(Cursor::new(storage.clone())).unwrap(),
                        &root,
                    )
                    .unwrap();
                let mut output = vec![0xaa; blocks * 512];
                if bad_root {
                    assert_eq!(
                        volume.read(&mut output).unwrap_err().kind(),
                        io::ErrorKind::InvalidData
                    );
                    assert!(output.iter().all(|b| *b == 0xaa));
                } else {
                    volume.read_exact(&mut output).unwrap();
                    assert!(output.iter().all(|b| *b == 0));
                }
                if bad_root && blocks == 1 {
                    assert!(reads.load(Ordering::Relaxed) > 0);
                } else {
                    assert_eq!(reads.load(Ordering::Relaxed), 0);
                }
            }
        }
    }
}

#[test]
fn first_read_tracking_never_bypasses_synthesized_zeroes() {
    let (storage, root) = image(&[0; 1024], HashType::Normal);
    let data = Data::new(vec![99; 1024]);
    *data.error.lock().unwrap() = Some(io::ErrorKind::PermissionDenied);
    let reads = data.reads.clone();
    let mut volume = Options::default()
        .with_ignore_zero_blocks(true)
        .with_check_at_most_once(true)
        .open(data, Hashes::open(Cursor::new(storage)).unwrap(), &root)
        .unwrap();
    for _ in 0..2 {
        let mut output = [0xaa; 1024];
        volume.read_exact(&mut output).unwrap();
        assert_eq!(output, [0; 1024]);
        volume.rewind().unwrap();
    }
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[test]
fn ignore_corruption_is_explicit_and_never_swallows_transport_errors() {
    let bytes = vec![7; 1024];
    let (storage, root) = image(&bytes, HashType::Normal);
    for corrupt_hashes in [false, true] {
        for policy in [CorruptionPolicy::Error, CorruptionPolicy::Ignore] {
            let mut storage = storage.clone();
            let mut data = bytes.clone();
            if corrupt_hashes {
                storage[512] ^= 1;
            } else {
                data[0] ^= 1;
            }
            let mut volume = Options::default()
                .with_corruption_policy(policy)
                .open(
                    Cursor::new(data.clone()),
                    Hashes::open(Cursor::new(storage)).unwrap(),
                    &root,
                )
                .unwrap();
            let mut output = [0xaa; 17];
            if policy == CorruptionPolicy::Ignore {
                volume.read_exact(&mut output).unwrap();
                assert_eq!(output, data[..17]);
            } else {
                assert_eq!(
                    volume.read(&mut output).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(output, [0xaa; 17]);
            }
        }
    }
    for error in [io::ErrorKind::InvalidData, io::ErrorKind::PermissionDenied] {
        for fail_hashes in [false, true] {
            let data = Data::new(bytes.clone());
            let hashes = Data::new(storage.clone());
            let flag = if fail_hashes {
                hashes.error.clone()
            } else {
                data.error.clone()
            };
            let hashes = Hashes::open(hashes).unwrap();
            *flag.lock().unwrap() = Some(error);
            let mut volume = Options::default()
                .with_corruption_policy(CorruptionPolicy::Ignore)
                .open(data, hashes, &root)
                .unwrap();
            assert_eq!(volume.read(&mut [0; 1]).unwrap_err().kind(), error);
        }
    }
}

#[test]
fn first_read_only_verification_tracks_success_not_failed_attempts() {
    let bytes = vec![7; 1024];
    let (storage, root) = image(&bytes, HashType::Normal);
    for once in [false, true] {
        let data = Data::new(bytes.clone());
        let shared = data.bytes.clone();
        let mut volume = Options::default()
            .with_check_at_most_once(once)
            .open(
                data,
                Hashes::open(Cursor::new(storage.clone())).unwrap(),
                &root,
            )
            .unwrap();
        volume.read_exact(&mut [0; 512]).unwrap();
        volume.read_exact(&mut [0; 512]).unwrap(); // evict the single-block cache
        shared.lock().unwrap()[0] = 9;
        volume.rewind().unwrap();
        let mut output = [0xaa; 1];
        if once {
            volume.read_exact(&mut output).unwrap();
            assert_eq!(output, [9]);
        } else {
            assert!(volume.read(&mut output).is_err());
            assert_eq!(output, [0xaa]);
        }
    }
    let mut bad = bytes;
    bad[0] ^= 1;
    let mut volume = Options::default()
        .with_check_at_most_once(true)
        .open(
            Cursor::new(bad),
            Hashes::open(Cursor::new(storage)).unwrap(),
            &root,
        )
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            volume.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn unsupported_options_fail_during_userspace_construction() {
    let (storage, root) = image(&[7; 512], HashType::Normal);
    let fec = Fec::new(DevId::new(7, 0).unwrap(), std::num::NonZeroU64::MIN, 2).unwrap();
    for options in [
        Options::default().with_hash_start_block(0),
        Options::default().with_try_verify_in_tasklet(true),
        Options::default().with_corruption_policy(CorruptionPolicy::Restart),
        Options::default().with_corruption_policy(CorruptionPolicy::Panic),
        Options::default().with_io_error_policy(IoErrorPolicy::Restart),
        Options::default().with_io_error_policy(IoErrorPolicy::Panic),
        Options::default().with_fec(fec),
        Options::default().with_root_hash_sig_key_desc(KeyDescription::try_from("key").unwrap()),
    ] {
        let hashes = Hashes::open(Cursor::new(storage.clone())).unwrap();
        let error = options
            .open(Cursor::new(vec![7; 512]), hashes, &root)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}

#[cfg(feature = "tokio")]
mod asynchronous {
    use super::{Data, image};
    use devmap_verity::traits::tokio::{Geometry, Open as _, OpenHashes as _};
    use devmap_verity::{CorruptionPolicy, HashType, Hashes, Options};
    use std::{
        io,
        num::NonZeroU32,
        pin::Pin,
        sync::atomic::Ordering,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _, ReadBuf};

    impl AsyncRead for Data {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let count = std::io::Read::read(self.get_mut(), output.initialize_unfilled())?;
            output.advance(count);
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncSeek for Data {
        fn start_seek(self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
            std::io::Seek::seek(self.get_mut(), position)?;
            Ok(())
        }
        fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
            Poll::Ready(Ok(self.position as u64))
        }
    }
    impl Geometry for Data {
        fn block_size(&self) -> io::Result<NonZeroU32> {
            Ok(NonZeroU32::MIN)
        }
        fn count(
            &mut self,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<u64>> + Send + '_>> {
            Box::pin(std::future::ready(Ok(
                self.bytes.lock().unwrap().len() as u64
            )))
        }
    }

    #[tokio::test]
    async fn zero_blocks_and_unsupported_options_have_async_semantics() {
        let (storage, root) = image(&[0; 1024], HashType::Normal);
        let data = Data::new(vec![99; 1024]);
        *data.error.lock().unwrap() = Some(io::ErrorKind::PermissionDenied);
        let reads = data.reads.clone();
        let hashes = Hashes::open(io::Cursor::new(storage.clone()))
            .await
            .unwrap();
        let mut volume = Options::default()
            .with_ignore_zero_blocks(true)
            .with_check_at_most_once(true)
            .open(data, hashes, &root)
            .await
            .unwrap();
        let mut output = [0xaa; 1024];
        volume.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [0; 1024]);
        volume.rewind().await.unwrap();
        output.fill(0xaa);
        volume.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [0; 1024]);
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        for options in [
            Options::default().with_hash_start_block(0),
            Options::default().with_try_verify_in_tasklet(true),
            Options::default().with_corruption_policy(CorruptionPolicy::Panic),
        ] {
            let hashes = Hashes::open(io::Cursor::new(storage.clone()))
                .await
                .unwrap();
            let error = options
                .open(Data::new(vec![0; 1024]), hashes, &root)
                .await
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
    }

    #[tokio::test]
    async fn first_read_only_and_ignore_policies_are_applied_by_the_async_reader() {
        let bytes = vec![7; 1024];
        let (storage, root) = image(&bytes, HashType::Normal);
        for once in [false, true] {
            let data = Data::new(bytes.clone());
            let shared = data.bytes.clone();
            let hashes = Hashes::open(io::Cursor::new(storage.clone()))
                .await
                .unwrap();
            let mut volume = Options::default()
                .with_check_at_most_once(once)
                .open(data, hashes, &root)
                .await
                .unwrap();
            volume.read_exact(&mut [0; 512]).await.unwrap();
            volume.read_exact(&mut [0; 512]).await.unwrap();
            shared.lock().unwrap()[0] = 9;
            volume.rewind().await.unwrap();
            let mut output = [0xaa; 1];
            if once {
                volume.read_exact(&mut output).await.unwrap();
                assert_eq!(output, [9]);
            } else {
                assert_eq!(
                    volume.read(&mut output).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(output, [0xaa]);
            }
        }
        for corrupt_tree in [false, true] {
            let mut storage = storage.clone();
            let mut bytes = bytes.clone();
            if corrupt_tree {
                storage[512] ^= 1;
            } else {
                bytes[0] ^= 1;
            }
            let hashes = Hashes::open(io::Cursor::new(storage)).await.unwrap();
            let mut volume = Options::default()
                .with_corruption_policy(CorruptionPolicy::Ignore)
                .open(Data::new(bytes.clone()), hashes, &root)
                .await
                .unwrap();
            let mut output = [0; 1024];
            volume.read_exact(&mut output).await.unwrap();
            assert_eq!(output.as_slice(), bytes);
        }
    }

    #[tokio::test]
    async fn ignore_does_not_suppress_async_transport_errors() {
        let (storage, root) = image(&[7; 1024], HashType::Normal);
        for fail_hashes in [false, true] {
            let data = Data::new(vec![7; 1024]);
            let hashes = Data::new(storage.clone());
            let flag = if fail_hashes {
                hashes.error.clone()
            } else {
                data.error.clone()
            };
            let hashes = Hashes::open(hashes).await.unwrap();
            *flag.lock().unwrap() = Some(io::ErrorKind::InvalidData);
            let mut volume = Options::default()
                .with_corruption_policy(CorruptionPolicy::Ignore)
                .open(data, hashes, &root)
                .await
                .unwrap();
            let mut output = [0xaa; 1];
            assert_eq!(
                volume.read(&mut output).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(output, [0xaa]);
        }
    }
}
