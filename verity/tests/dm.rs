// SPDX-License-Identifier: Apache-2.0

use devmap_core::DevId;
use devmap_verity::{
    HashType, Hashes,
    dm::{Builder, CorruptionPolicy as C, Fec, Info, IoErrorPolicy as E, VerityTarget},
    traits::std::OpenHashes as _,
};
use std::{
    io::{self, Cursor},
    num::NonZeroU64,
};
mod common;

fn id(minor: u32) -> DevId {
    DevId::new(252, minor).unwrap()
}
fn builder() -> Builder {
    Builder::new(NonZeroU64::new(3).unwrap())
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
}
fn finish(builder: Builder) -> VerityTarget {
    builder.build(id(1), id(2), &[0xbb; 32]).unwrap()
}

#[test]
fn all_parameters_round_trip_including_every_policy_combination() {
    for corruption in [C::Error, C::Ignore, C::Restart, C::Panic] {
        for errors in [E::Error, E::Restart, E::Panic] {
            for bits in 0u8..32 {
                let mut b = builder()
                    .hash_type(HashType::ChromeOs)
                    .hash_start_block(7)
                    .salt(&[0xaa; 257])
                    .corruption_policy(corruption)
                    .io_error_policy(errors)
                    .ignore_zero_blocks(bits & 1 != 0)
                    .check_at_most_once(bits & 2 != 0)
                    .try_verify_in_tasklet(bits & 4 != 0);
                if bits & 8 != 0 {
                    b = b.fec(
                        Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2)
                            .unwrap()
                            .start(11),
                    );
                }
                if bits & 16 != 0 {
                    b = b
                        .root_hash_sig_key_desc("signature with spaces\\and-backslash")
                        .unwrap();
                }
                let target = finish(b);
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
        let target = Builder::from(hashes.header())
            .header_offset_bytes(8192)
            .unwrap()
            .build(id(1), id(2), &vec![0; digest_size])
            .unwrap();
        assert_eq!(target.hash_start_block(), 3);
        assert_eq!(target.algorithm(), algorithm.as_ref());
        assert_eq!(target.data_block_size().get(), 512);
        assert_eq!(target.hash_block_size().get(), 4096);
        assert_eq!(
            target.to_header(hashes.header().uuid()).unwrap(),
            *hashes.header()
        );
    }
}

#[test]
fn raw_kernel_algorithms_and_headerless_trees_are_representable() {
    let target = finish(
        builder()
            .algorithm("future-kernel-hash")
            .unwrap()
            .hash_start_block(0)
            .salt(&[]),
    );
    let text = target.to_string();
    assert!(text.ends_with(" -"));
    assert_eq!(text.parse::<VerityTarget>().unwrap(), target);
    assert_eq!(
        target.to_header([0; 16]).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
    assert!(
        finish(builder().salt(&[0; 257]))
            .to_header([0; 16])
            .is_err()
    );
}

#[test]
fn invalid_parameters_and_conflicting_options_are_rejected() {
    for size in [0, 511, 513, 1 << 31] {
        assert!(builder().data_block_size(size).is_err());
        assert!(builder().hash_block_size(size).is_err());
    }
    assert!(builder().header_offset_bytes(1).is_err());
    assert!(builder().algorithm("").is_err());
    assert!(builder().algorithm("sha 256").is_err());
    assert!(builder().root_hash_sig_key_desc("bad\0key").is_err());
    assert!(builder().build(id(1), id(2), &[0; 31]).is_err());
    assert!(
        Builder::new(NonZeroU64::new(u64::MAX).unwrap())
            .build(id(1), id(2), &[0; 32])
            .is_err()
    );
    assert!(
        builder()
            .hash_start_block(u64::MAX)
            .build(id(1), id(2), &[0; 32])
            .is_err()
    );
    for roots in [0, 1, 25, 255] {
        assert!(Fec::new(id(3), NonZeroU64::new(4).unwrap(), roots).is_err());
    }
    assert!(
        builder()
            .fec(Fec::new(id(3), NonZeroU64::new(3).unwrap(), 2).unwrap())
            .build(id(1), id(2), &[0; 32])
            .is_err()
    );
    assert!(
        builder()
            .hash_block_size(4096)
            .unwrap()
            .fec(Fec::new(id(3), NonZeroU64::new(4).unwrap(), 2).unwrap())
            .build(id(1), id(2), &[0; 32])
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
