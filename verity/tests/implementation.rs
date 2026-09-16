// SPDX-License-Identifier: Apache-2.0

#![cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]

use std::io::{self, Cursor, Read as _, Seek as _, SeekFrom};
use std::num::NonZeroU32;

use devmap_verity::{Algorithm, Hashes, Options, Scheme, traits::std::*};

mod common;

// With all features these branches become true, but isolated builds need the mapping.
#[allow(clippy::match_like_matches_macro)]
fn available(algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::Sha1 => cfg!(feature = "sha1"),
        Algorithm::Sha224 | Algorithm::Sha256 | Algorithm::Sha384 | Algorithm::Sha512 => {
            cfg!(feature = "sha2")
        }
        Algorithm::Ripemd160 => cfg!(feature = "ripemd"),
        Algorithm::Whirlpool => cfg!(feature = "whirlpool"),
        Algorithm::Sha3_224 | Algorithm::Sha3_256 | Algorithm::Sha3_384 | Algorithm::Sha3_512 => {
            cfg!(feature = "sha3")
        }
        Algorithm::Streebog256 | Algorithm::Streebog512 => cfg!(feature = "streebog"),
        Algorithm::Sm3 => cfg!(feature = "sm3"),
        Algorithm::Blake2b160
        | Algorithm::Blake2b256
        | Algorithm::Blake2b384
        | Algorithm::Blake2b512
        | Algorithm::Blake2s128
        | Algorithm::Blake2s160
        | Algorithm::Blake2s224
        | Algorithm::Blake2s256 => cfg!(feature = "blake2"),
        _ => false,
    }
}

#[test]
fn every_enabled_algorithm_formats_and_authenticates() {
    for &(_, algorithm, digest_size) in common::ALGORITHMS {
        if !available(algorithm) {
            continue;
        }
        for blocks in [1usize, 2, 129] {
            for hash_type in [
                devmap_verity::HashType::Normal,
                devmap_verity::HashType::ChromeOs,
            ] {
                let data: Vec<_> = (0..blocks * 512)
                    .map(|n| u8::try_from(n % 251).unwrap())
                    .collect();
                let block_size = NonZeroU32::new(512).unwrap();
                let mut storage = Cursor::new(Vec::new()).scale(block_size).unwrap();
                let (_, root) = Scheme::default()
                    .with_algorithm(algorithm)
                    .with_hash_type(hash_type)
                    .with_salt(&[9; 17])
                    .unwrap()
                    .format(
                        Cursor::new(&data).scale(block_size).unwrap(),
                        &mut storage,
                        [7; 16],
                    )
                    .unwrap();
                assert_eq!(root.len(), digest_size);
                let hashes = Hashes::open(storage).unwrap();
                let mut device = Options::default()
                    .open(Cursor::new(&data), hashes, &root)
                    .unwrap();
                let mut actual = Vec::new();
                device.read_to_end(&mut actual).unwrap();
                assert_eq!(actual, data);
            }
        }
    }
}

#[test]
fn unavailable_algorithms_allow_inspection_and_composition_but_not_hashing() {
    for &(name, algorithm, digest_size) in common::ALGORITHMS {
        if available(algorithm) {
            continue;
        }
        let mut bytes = vec![0; 8192];
        bytes[..512].copy_from_slice(&common::header(name));
        let hashes = Hashes::open(Cursor::new(bytes)).unwrap();
        let mut device = Options::default()
            .open(Cursor::new(vec![0; 1536]), hashes, &vec![0; digest_size])
            .unwrap();
        assert_eq!(device.hashes().scheme().algorithm, algorithm);
        let mut output = [0xaa; 1];
        assert_eq!(
            device.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(output, [0xaa]);
        assert_eq!(device.stream_position().unwrap(), 0);

        let block_size = NonZeroU32::new(512).unwrap();
        let mut bytes = Cursor::new(Vec::new());
        let error = Scheme::default()
            .with_algorithm(algorithm)
            .format(
                Cursor::new(vec![0; 512]).scale(block_size).unwrap(),
                (&mut bytes).scale(block_size).unwrap(),
                [0; 16],
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(bytes.into_inner(), [] as [u8; 0]);
    }
}

#[test]
fn failed_authentication_cannot_reuse_a_previous_blocks_cache_tag() {
    let algorithm = common::ALGORITHMS
        .iter()
        .map(|&(_, a, _)| a)
        .find(|&a| available(a))
        .unwrap();
    let block_size = NonZeroU32::new(512).unwrap();
    let data = [vec![0x11; 512], vec![0x22; 512]].concat();
    let mut storage = Cursor::new(Vec::new()).scale(block_size).unwrap();
    let (_, root) = Scheme::default()
        .with_algorithm(algorithm)
        .format(
            Cursor::new(&data).scale(block_size).unwrap(),
            &mut storage,
            [0; 16],
        )
        .unwrap();
    let mut corrupt = data;
    corrupt[512] ^= 1;
    let mut device = Options::default()
        .open(Cursor::new(corrupt), Hashes::open(storage).unwrap(), &root)
        .unwrap();
    let mut output = [0; 16];
    device.read_exact(&mut output).unwrap();
    assert_eq!(output, [0x11; 16]);
    device.seek(SeekFrom::Start(512)).unwrap();
    output.fill(0xaa);
    assert_eq!(
        device.read(&mut output).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(output, [0xaa; 16]);
    assert_eq!(device.stream_position().unwrap(), 512);
    device.rewind().unwrap();
    device.read_exact(&mut output).unwrap();
    assert_eq!(output, [0x11; 16]);
}
