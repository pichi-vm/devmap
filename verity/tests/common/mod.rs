// SPDX-License-Identifier: Apache-2.0

use devmap_verity::Algorithm;

pub(crate) const ALGORITHMS: &[(&str, Algorithm, usize)] = &[
    ("sha1", Algorithm::Sha1, 20),
    ("sha224", Algorithm::Sha224, 28),
    ("sha256", Algorithm::Sha256, 32),
    ("sha384", Algorithm::Sha384, 48),
    ("sha512", Algorithm::Sha512, 64),
    ("rmd160", Algorithm::Ripemd160, 20),
    ("wp512", Algorithm::Whirlpool, 64),
    ("sha3-224", Algorithm::Sha3_224, 28),
    ("sha3-256", Algorithm::Sha3_256, 32),
    ("sha3-384", Algorithm::Sha3_384, 48),
    ("sha3-512", Algorithm::Sha3_512, 64),
    ("streebog256", Algorithm::Streebog256, 32),
    ("streebog512", Algorithm::Streebog512, 64),
    ("sm3", Algorithm::Sm3, 32),
    ("blake2b-160", Algorithm::Blake2b160, 20),
    ("blake2b-256", Algorithm::Blake2b256, 32),
    ("blake2b-384", Algorithm::Blake2b384, 48),
    ("blake2b-512", Algorithm::Blake2b512, 64),
    ("blake2s-128", Algorithm::Blake2s128, 16),
    ("blake2s-160", Algorithm::Blake2s160, 20),
    ("blake2s-224", Algorithm::Blake2s224, 28),
    ("blake2s-256", Algorithm::Blake2s256, 32),
];

pub(crate) fn header(name: &str) -> [u8; 512] {
    let mut bytes = [0; 512];
    bytes[..8].copy_from_slice(b"verity\0\0");
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..32].fill(0x5a);
    bytes[32..32 + name.len()].copy_from_slice(name.as_bytes());
    bytes[64..68].copy_from_slice(&512u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&4096u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&3u64.to_le_bytes());
    bytes[80..82].copy_from_slice(&3u16.to_le_bytes());
    bytes[88..91].copy_from_slice(&[1, 2, 3]);
    bytes
}
