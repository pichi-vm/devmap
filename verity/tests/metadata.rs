// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "sha1"))]
use devmap_verity::Unverified;
use devmap_verity::{Algorithm, TreeWriter, Verified};
use std::io::{Cursor, Write};
use std::num::NonZeroU64;

#[test]
fn every_algorithm_name_is_available_independently_of_hash_features() {
    let algorithms = [
        ("sha1", Algorithm::Sha1),
        ("sha224", Algorithm::Sha224),
        ("sha256", Algorithm::Sha256),
        ("sha384", Algorithm::Sha384),
        ("sha512", Algorithm::Sha512),
        ("rmd160", Algorithm::Ripemd160),
        ("wp512", Algorithm::Whirlpool),
        ("sha3-224", Algorithm::Sha3_224),
        ("sha3-256", Algorithm::Sha3_256),
        ("sha3-384", Algorithm::Sha3_384),
        ("sha3-512", Algorithm::Sha3_512),
        ("streebog256", Algorithm::Streebog256),
        ("streebog512", Algorithm::Streebog512),
        ("sm3", Algorithm::Sm3),
        ("blake2b-160", Algorithm::Blake2b160),
        ("blake2b-256", Algorithm::Blake2b256),
        ("blake2b-384", Algorithm::Blake2b384),
        ("blake2b-512", Algorithm::Blake2b512),
        ("blake2s-128", Algorithm::Blake2s128),
        ("blake2s-160", Algorithm::Blake2s160),
        ("blake2s-224", Algorithm::Blake2s224),
        ("blake2s-256", Algorithm::Blake2s256),
    ];

    for (name, algorithm) in algorithms {
        assert_eq!(name.parse::<Algorithm>().unwrap(), algorithm);
        assert_eq!(algorithm.as_ref(), name);
        assert_eq!(algorithm.to_string(), name);
    }
}

#[test]
fn every_enabled_algorithm_can_write_a_tree() {
    let algorithms: &[Algorithm] = &[
        #[cfg(feature = "sha1")]
        Algorithm::Sha1,
        #[cfg(feature = "sha2")]
        Algorithm::Sha224,
        #[cfg(feature = "sha2")]
        Algorithm::Sha256,
        #[cfg(feature = "sha2")]
        Algorithm::Sha384,
        #[cfg(feature = "sha2")]
        Algorithm::Sha512,
        #[cfg(feature = "ripemd")]
        Algorithm::Ripemd160,
        #[cfg(feature = "whirlpool")]
        Algorithm::Whirlpool,
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_224,
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_256,
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_384,
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_512,
        #[cfg(feature = "streebog")]
        Algorithm::Streebog256,
        #[cfg(feature = "streebog")]
        Algorithm::Streebog512,
        #[cfg(feature = "sm3")]
        Algorithm::Sm3,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2b160,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2b256,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2b384,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2b512,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2s128,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2s160,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2s224,
        #[cfg(feature = "blake2")]
        Algorithm::Blake2s256,
    ];

    for &algorithm in algorithms {
        let superblock = Verified::builder()
            .algorithm(algorithm)
            .data_block_size(512)
            .unwrap()
            .hash_block_size(512)
            .unwrap()
            .build([0; 16], NonZeroU64::MIN)
            .unwrap();
        let mut output = Cursor::new(Vec::new());
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        tree.write_all(&[0; 512]).unwrap();
        tree.flush().unwrap();
        assert_ne!(tree.digest().unwrap(), []);
    }
}

#[cfg(not(feature = "sha1"))]
#[test]
fn a_disabled_algorithm_remains_valid_superblock_metadata() {
    let superblock = Verified::builder()
        .algorithm(Algorithm::Sha1)
        .build([0; 16], NonZeroU64::MIN)
        .unwrap();
    let bytes = Unverified::from(&superblock);
    let decoded = Verified::try_from(bytes).unwrap();

    assert_eq!(decoded.algorithm(), Algorithm::Sha1);
    let error = TreeWriter::new(Cursor::new(Vec::<u8>::new()), decoded)
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}
