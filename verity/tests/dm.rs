// SPDX-License-Identifier: Apache-2.0

use devmap_core::parse::DevId;
use devmap_verity::{
    Builder, HashType, Hashes, Parameters,
    dm::{CorruptionPolicy as C, Fec, Info, IoErrorPolicy as E, VerityTarget},
    traits::std::OpenHashes as _,
};
use std::{io::Cursor, num::NonZeroU64};
mod common;

fn id(minor: u32) -> DevId {
    DevId::new(252, minor).unwrap()
}
fn builder() -> Builder {
    Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
}
fn finish(builder: Builder) -> VerityTarget {
    builder
        .build(NonZeroU64::new(3).unwrap())
        .unwrap()
        .target(id(1), id(2), &[0xbb; 32])
        .unwrap()
}

#[test]
fn all_parameters_round_trip_including_every_policy_combination() {
    for corruption in [C::Error, C::Ignore, C::Restart, C::Panic] {
        for errors in [E::Error, E::Restart, E::Panic] {
            for bits in 0u8..32 {
                let mut target = finish(builder().hash_type(HashType::ChromeOs).salt(&[0xaa; 257]))
                    .with_hash_start_block(7)
                    .unwrap()
                    .with_corruption_policy(corruption)
                    .with_io_error_policy(errors)
                    .with_ignore_zero_blocks(bits & 1 != 0)
                    .with_check_at_most_once(bits & 2 != 0)
                    .unwrap()
                    .with_try_verify_in_tasklet(bits & 4 != 0);
                if bits & 8 != 0 {
                    target = target
                        .with_fec(
                            Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2)
                                .unwrap()
                                .start(11),
                        )
                        .unwrap();
                }
                if bits & 16 != 0 {
                    target = target
                        .with_root_hash_sig_key_desc("signature with spaces\\and-backslash")
                        .unwrap();
                }
                let text = target.to_string();
                assert_eq!(text.parse::<VerityTarget>().unwrap(), target, "{text}");
                assert_eq!(target.data_sectors(), 3);
                assert_eq!(target.hash_start_block(), 7);
                assert_eq!(target.corruption_policy(), corruption);
                assert_eq!(target.io_error_policy(), errors);
            }
        }
    }
}

#[test]
fn header_conversion_needs_no_hashing_and_preserves_all_shared_fields() {
    for &(name, algorithm, digest_size) in common::ALGORITHMS {
        let hashes = Hashes::open(Cursor::new(common::header(name))).unwrap();
        let target = hashes
            .parameters()
            .target(id(1), id(2), &vec![0; digest_size])
            .unwrap()
            .with_header_offset_bytes(8192)
            .unwrap();
        assert_eq!(target.hash_start_block(), 3);
        assert_eq!(target.parameters().algorithm(), algorithm);
        assert_eq!(target.parameters().data_block_size().get(), 512);
        assert_eq!(target.parameters().hash_block_size().get(), 4096);
        assert_eq!(target.parameters(), hashes.parameters());
    }
}

#[test]
fn headerless_trees_and_large_salts_need_no_header() {
    let target = finish(builder().salt(&[0xaa; 257]))
        .with_hash_start_block(0)
        .unwrap();
    assert_eq!(target.to_string().parse::<VerityTarget>().unwrap(), target);
    assert_eq!(target.hash_start_block(), 0);
    assert_eq!(target.parameters().salt().len(), 257);
    assert!(finish(builder()).to_string().ends_with(" -"));
}

#[test]
fn unknown_algorithms_are_rejected() {
    let text = finish(builder()).to_string();
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
    for size in [0, 511, 513, 1 << 31] {
        assert!(builder().data_block_size(size).is_err());
        assert!(builder().hash_block_size(size).is_err());
    }
    assert!(finish(builder()).with_header_offset_bytes(1).is_err());
    assert!(
        finish(builder())
            .with_root_hash_sig_key_desc("bad\0key")
            .is_err()
    );
    assert!(
        builder()
            .build(NonZeroU64::new(3).unwrap())
            .unwrap()
            .target(id(1), id(2), &[0; 31])
            .is_err()
    );
    assert!(
        Parameters::builder()
            .build(NonZeroU64::new(u64::MAX).unwrap())
            .is_err()
    );
    assert!(finish(builder()).with_hash_start_block(u64::MAX).is_err());
    for roots in [0, 1, 25, 255] {
        assert!(Fec::new(id(3), NonZeroU64::new(4).unwrap(), roots).is_err());
    }
    assert!(
        finish(builder())
            .with_fec(Fec::new(id(3), NonZeroU64::new(3).unwrap(), 2).unwrap())
            .is_err()
    );
    assert!(
        finish(builder().hash_block_size(4096).unwrap())
            .with_fec(Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2).unwrap())
            .is_err()
    );
    let base = finish(builder()).to_string();
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
        finish(builder())
    );
}

#[test]
fn status_retains_corruption_and_fec_counts() {
    for text in ["V -", "C 12", "V 0"] {
        assert_eq!(text.parse::<Info>().unwrap().to_string(), text);
    }
}
