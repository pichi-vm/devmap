// SPDX-License-Identifier: Apache-2.0

// `i % 251` is provably in u8 range; keep the fixture generation readable.
#![allow(clippy::cast_possible_truncation)]

use devmap_verity::*;
use std::io::{Cursor, Read as _, Write as _};
use std::num::NonZeroU64;

/// Format a 16-byte UUID as the canonical 8-4-4-4-12 hex string that
/// `veritysetup format --uuid` accepts and writes back byte-identically.
fn format_uuid(u: &[u8; 16]) -> String {
    let h = hex::encode(u);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn assert_matches_veritysetup(
    blocks: usize,
    hash_type: HashType,
    algorithm: Algorithm,
    required: bool,
) {
    if std::process::Command::new("veritysetup")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("veritysetup absent — skipping cross-check");
        return;
    }
    let mut data = vec![0u8; 4096 * blocks];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let salt: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(1))
        .collect();
    let uuid = [0x5a; 16];
    let superblock = Verified::builder()
        .algorithm(algorithm)
        .hash_type(hash_type)
        .data_block_size(4096)
        .unwrap()
        .hash_block_size(4096)
        .unwrap()
        .salt(&salt)
        .unwrap()
        .build(
            uuid,
            NonZeroU64::new(blocks as u64).expect("test data is nonempty"),
        )
        .unwrap();
    let mut blob = Cursor::new(Vec::new());
    let bytes = Unverified::from(&superblock);
    blob.write_all(bytes.as_ref()).unwrap();
    std::io::copy(
        &mut std::io::repeat(0).take(superblock.padding()),
        &mut blob,
    )
    .unwrap();
    let root_hash = {
        let mut tree = TreeWriter::new(&mut blob, superblock).unwrap();
        tree.write_all(&data).unwrap();
        tree.flush().unwrap();
        tree.digest().unwrap().to_vec()
    };
    let blob = blob.into_inner();

    let tmp = tempfile::TempDir::new().unwrap();
    let datap = tmp.path().join("data.img");
    let hashp = tmp.path().join("hash.img");
    std::fs::write(&datap, &data).unwrap();

    let o = std::process::Command::new("veritysetup")
        .args([
            "format",
            "--data-block-size",
            "4096",
            "--hash-block-size",
            "4096",
            "--hash",
            algorithm.as_ref(),
            "--format",
            &hash_type.to_string(),
            "--salt",
            &hex::encode(&salt),
            "--uuid",
            &format_uuid(&uuid),
        ])
        .arg(&datap)
        .arg(&hashp)
        .output()
        .unwrap();
    if !required && !o.status.success() {
        eprintln!(
            "veritysetup does not provide {algorithm} through its compiled crypto backend — skipping cross-check: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        return;
    }
    assert!(
        o.status.success(),
        "veritysetup format failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let stdout = String::from_utf8_lossy(&o.stdout);
    let vroot = stdout
        .lines()
        .find_map(|l| l.strip_prefix("Root hash:"))
        .map(|s| s.trim().to_string())
        .expect("veritysetup must print a Root hash line");
    assert_eq!(
        vroot,
        hex::encode(root_hash),
        "veritysetup root hash must equal the internal producer's"
    );
    let vblob = std::fs::read(&hashp).unwrap();
    assert_eq!(
        vblob, blob,
        "veritysetup hash device must be byte-identical to the internal verity blob"
    );
}

#[test]
fn matches_veritysetup_without_a_stored_tree_level() {
    assert_matches_veritysetup(1, HashType::Normal, Algorithm::Sha256, true);
}

#[test]
fn matches_veritysetup_with_multiple_tree_levels() {
    assert_matches_veritysetup(300, HashType::Normal, Algorithm::Sha256, true);
}

#[test]
fn chrome_os_fanout_matches_veritysetup() {
    for (blocks, algorithm) in [
        (129, Algorithm::Sha1),
        (129, Algorithm::Sha224),
        (65, Algorithm::Sha384),
    ] {
        assert_matches_veritysetup(blocks, HashType::ChromeOs, algorithm, true);
    }
}

#[test]
fn every_locally_available_algorithm_matches_veritysetup() {
    let mut algorithms = Vec::new();
    #[cfg(feature = "sha1")]
    algorithms.push(Algorithm::Sha1);
    #[cfg(feature = "sha2")]
    algorithms.extend([
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
    ]);
    #[cfg(feature = "ripemd")]
    algorithms.push(Algorithm::Ripemd160);
    #[cfg(feature = "whirlpool")]
    algorithms.push(Algorithm::Whirlpool);
    #[cfg(feature = "sha3")]
    algorithms.extend([
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
    ]);
    #[cfg(feature = "streebog")]
    algorithms.extend([Algorithm::Streebog256, Algorithm::Streebog512]);
    #[cfg(feature = "sm3")]
    algorithms.push(Algorithm::Sm3);
    #[cfg(feature = "blake2")]
    algorithms.extend([
        Algorithm::Blake2b160,
        Algorithm::Blake2b256,
        Algorithm::Blake2b384,
        Algorithm::Blake2b512,
        Algorithm::Blake2s128,
        Algorithm::Blake2s160,
        Algorithm::Blake2s224,
        Algorithm::Blake2s256,
    ]);

    for algorithm in algorithms {
        assert_matches_veritysetup(65, HashType::Normal, algorithm, false);
    }
}
