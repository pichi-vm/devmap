// SPDX-License-Identifier: Apache-2.0

use devmap_core::parse::DevId;
use devmap_verity::{
    BlockSize, CorruptionPolicy as C, Fec, HashType, Hashes, Info, IoErrorPolicy as E,
    KeyDescription, Options, Scheme, Shape, VerityTarget, traits::std::OpenHashes as _,
};
use std::{io::Cursor, num::NonZeroU64};
mod common;

fn id(minor: u32) -> DevId {
    DevId::new(252, minor).unwrap()
}
fn shape() -> Shape {
    Shape::new(NonZeroU64::new(3).unwrap())
        .with_data_block_size(512u32.try_into().unwrap())
        .with_hash_block_size(512u32.try_into().unwrap())
}
fn finish(options: Options<'_>) -> VerityTarget {
    options
        .target(Scheme::default(), shape(), id(1), id(2), &[0xbb; 32])
        .unwrap()
}

#[test]
fn all_parameters_round_trip_including_every_policy_combination() {
    for corruption in [C::Error, C::Ignore, C::Restart, C::Panic] {
        for errors in [E::Error, E::Restart, E::Panic] {
            for bits in 0u8..32 {
                let scheme = Scheme::default()
                    .with_hash_type(HashType::ChromeOs)
                    .with_salt(&[0xaa; 256])
                    .unwrap();
                let mut options = Options::default()
                    .with_hash_start_block(7)
                    .with_corruption_policy(corruption)
                    .with_io_error_policy(errors)
                    .with_ignore_zero_blocks(bits & 1 != 0)
                    .with_check_at_most_once(bits & 2 != 0)
                    .with_try_verify_in_tasklet(bits & 4 != 0);
                if bits & 8 != 0 {
                    options = options.with_fec(
                        Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2)
                            .unwrap()
                            .start(11),
                    );
                }
                if bits & 16 != 0 {
                    options = options.with_root_hash_sig_key_desc(
                        KeyDescription::try_from("signature with spaces\\and-backslash").unwrap(),
                    );
                }
                let target = options
                    .target(scheme, shape(), id(1), id(2), &[0xbb; 32])
                    .unwrap();
                let text = target.to_string();
                assert_eq!(text.parse::<VerityTarget>().unwrap(), target, "{text}");
                assert_eq!(target.data_sectors(), 3);
                assert_eq!(target.options().hash_start_block, 7);
                assert_eq!(target.options().corruption_policy, corruption);
                assert_eq!(target.options().io_error_policy, errors);
            }
        }
    }
}

#[test]
fn header_conversion_needs_no_hashing_and_preserves_all_shared_fields() {
    for &(name, algorithm, digest_size) in common::ALGORITHMS {
        let hashes = Hashes::open(Cursor::new(common::header(name))).unwrap();
        let target = Options::default()
            .with_header_offset_bytes(8192, hashes.shape().hash_block_size)
            .unwrap()
            .target(
                hashes.scheme(),
                hashes.shape(),
                id(1),
                id(2),
                &vec![0; digest_size],
            )
            .unwrap();
        assert_eq!(target.options().hash_start_block, 3);
        assert_eq!(target.scheme().algorithm, algorithm);
        assert_eq!(u32::from(target.shape().data_block_size), 512);
        assert_eq!(u32::from(target.shape().hash_block_size), 4096);
        assert_eq!(target.scheme(), hashes.scheme());
        assert_eq!(target.shape(), hashes.shape());
    }
}

#[test]
fn headerless_trees_and_salt_limits() {
    let scheme = Scheme::default().with_salt(&[0xaa; 256]).unwrap();
    let target = Options::default()
        .with_hash_start_block(0)
        .target(scheme, shape(), id(1), id(2), &[0; 32])
        .unwrap();
    assert_eq!(target.to_string().parse::<VerityTarget>().unwrap(), target);
    assert_eq!(target.options().hash_start_block, 0);
    let long = target
        .to_string()
        .replace(&"aa".repeat(256), &"aa".repeat(257));
    assert!(long.parse::<VerityTarget>().is_err());
    let escaped = target
        .to_string()
        .replace(&"aa".repeat(256), &"\\a".repeat(512));
    assert_eq!(escaped.parse::<VerityTarget>().unwrap(), target);
    assert!(finish(Options::default()).to_string().ends_with(" -"));
}

#[test]
fn unknown_algorithms_are_rejected() {
    let text = finish(Options::default()).to_string();
    assert!(
        text.replace("sha256", "future-kernel-hash")
            .parse::<VerityTarget>()
            .is_err()
    );
    assert!(text.replace("sha256", "").parse::<VerityTarget>().is_err());
    assert!(
        text.replace("sha256", "sha 256")
            .parse::<VerityTarget>()
            .is_err()
    );
}

#[test]
fn invalid_parameters_and_conflicting_options_are_rejected() {
    for size in [0u32, 511, 513, 1 << 31] {
        assert!(BlockSize::try_from(size).is_err());
    }
    assert!(
        Options::default()
            .with_header_offset_bytes(1, BlockSize::default())
            .is_err()
    );
    assert!(KeyDescription::try_from("bad\0key").is_err());
    assert!(
        Options::default()
            .target(Scheme::default(), shape(), id(1), id(2), &[0; 31])
            .is_err()
    );
    assert!(
        Options::default()
            .target(
                Scheme::default(),
                Shape::new(NonZeroU64::new(u64::MAX).unwrap()),
                id(1),
                id(2),
                &[0; 32]
            )
            .is_err()
    );
    assert!(
        Options::default()
            .with_hash_start_block(u64::MAX)
            .target(Scheme::default(), shape(), id(1), id(2), &[0; 32])
            .is_err()
    );
    for roots in [0, 1, 25, 255] {
        assert!(Fec::new(id(3), NonZeroU64::new(4).unwrap(), roots).is_err());
    }
    let fec = Fec::new(id(3), NonZeroU64::new(3).unwrap(), 2).unwrap();
    assert!(
        Options::default()
            .with_fec(fec)
            .target(Scheme::default(), shape(), id(1), id(2), &[0; 32])
            .is_err()
    );
    let fec = Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2).unwrap();
    assert!(
        Options::default()
            .with_fec(fec)
            .target(
                Scheme::default(),
                shape().with_hash_block_size(BlockSize::default()),
                id(1),
                id(2),
                &[0; 32]
            )
            .is_err()
    );
    let base = finish(Options::default()).to_string();
    for extra in [
        "2 ignore_corruption restart_on_corruption",
        "2 restart_on_error panic_on_error",
        "2 unknown_option value",
        "1 ignore_corruption trailing",
        "2 fec_roots 1",
        "2 root_hash_sig_key_desc",
        "0 extra",
    ] {
        assert!(
            format!("{base} {extra}").parse::<VerityTarget>().is_err(),
            "{extra}"
        );
    }
    assert!(
        base.replace(&"bb".repeat(32), "é")
            .parse::<VerityTarget>()
            .is_err()
    );
    assert!(
        base.replace(&"bb".repeat(32), "abc")
            .parse::<VerityTarget>()
            .is_err()
    );
    assert!(
        base.replace(&"bb".repeat(32), "zz")
            .parse::<VerityTarget>()
            .is_err()
    );
    assert_eq!(
        format!("{base} 0").parse::<VerityTarget>().unwrap(),
        finish(Options::default())
    );
}

#[test]
fn status_retains_corruption_and_fec_counts() {
    for text in ["V -", "C 12", "V 0"] {
        assert_eq!(text.parse::<Info>().unwrap().to_string(), text);
    }
}
