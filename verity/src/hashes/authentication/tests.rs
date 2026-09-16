// SPDX-License-Identifier: Apache-2.0

use crate::traits::std::{Format as _, OpenHashes as _, Scale as _};
use crate::{HashType, Hashes, Scheme};
use std::{
    io::{self, Cursor},
    num::NonZeroU32,
};

fn image(blocks: usize, hash_type: HashType) -> (Vec<u8>, Vec<u8>, Box<[u8]>) {
    let data: Vec<_> = (0..blocks * 512).map(|n| (n % 251) as u8).collect();
    let size = NonZeroU32::new(512).unwrap();
    let (hashes, root) = Scheme::default()
        .with_hash_type(hash_type)
        .with_salt(&[3; 17])
        .unwrap()
        .format(
            Cursor::new(&data).scale_to(size).unwrap(),
            Cursor::new(Vec::new()).scale_to(size).unwrap(),
            [0; 16],
        )
        .unwrap();
    (data, hashes.into_inner().into_inner().into_inner(), root)
}

#[test]
fn lookup_authenticates_the_expected_digest_without_receiving_data() {
    for hash_type in [HashType::Normal, HashType::ChromeOs] {
        for blocks in [1, 2, 17, 257] {
            let (data, storage, root) = image(blocks, hash_type);
            let mut hashes = Hashes::open(Cursor::new(storage)).unwrap();
            let scheme = hashes.scheme();
            let mut hasher = scheme.algorithm.hasher().unwrap();
            for block in [0, blocks - 1] {
                let mut expected = vec![0; scheme.algorithm.digest_size()];
                scheme
                    .hash_type
                    .digest(
                        hasher.as_mut(),
                        scheme.salt.as_slice(),
                        &data[block * 512..(block + 1) * 512],
                        &mut expected,
                    )
                    .unwrap();
                assert_eq!(hashes.lookup(block as u64, &root).unwrap(), expected);
            }
            let mut different = root.clone();
            different[0] ^= 1;
            if blocks == 1 {
                assert_eq!(hashes.lookup(0, &different).unwrap(), different.as_ref());
            } else {
                assert_eq!(
                    hashes.lookup(0, &different).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
            }
            hashes.lookup(0, &root).unwrap();
            assert_eq!(
                hashes.lookup(blocks as u64, &root).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                hashes.lookup(0, &root[..31]).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}

#[test]
fn corruption_at_every_tree_level_prevents_a_digest_from_being_returned() {
    let (_, storage, root) = image(257, HashType::Normal);
    let hashes = Hashes::open(Cursor::new(storage.clone())).unwrap();
    for offset in &hashes.layout.level_offsets {
        let mut corrupt = storage.clone();
        corrupt[512 + *offset as usize] ^= 1;
        let mut hashes = Hashes::open(Cursor::new(corrupt)).unwrap();
        assert_eq!(
            hashes.lookup(0, &root).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            hashes.lookup(0, &root).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn async_lookup_rebinds_the_root_and_returns_only_authenticated_digests() {
    use std::future::poll_fn;
    for blocks in [1, 17, 257] {
        let (_, storage, root) = image(blocks, HashType::Normal);
        let mut hashes =
            <Hashes<_> as crate::traits::tokio::OpenHashes<_>>::open(Cursor::new(storage))
                .await
                .unwrap();
        let original = poll_fn(|cx| {
            hashes
                .poll_lookup(cx, 0, &root)
                .map(|result| result.map(<[u8]>::to_vec))
        })
        .await
        .unwrap();
        let mut wrong = root.clone();
        wrong[0] ^= 1;
        let result = poll_fn(|cx| {
            hashes
                .poll_lookup(cx, 0, &wrong)
                .map(|result| result.map(<[u8]>::to_vec))
        })
        .await;
        if blocks == 1 {
            assert_eq!(result.unwrap(), wrong.as_ref());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        let again = poll_fn(|cx| {
            hashes
                .poll_lookup(cx, 0, &root)
                .map(|result| result.map(<[u8]>::to_vec))
        })
        .await
        .unwrap();
        assert_eq!(again, original);
    }
}
