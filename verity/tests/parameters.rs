// SPDX-License-Identifier: Apache-2.0

use devmap_core::parse::DevId;
use devmap_verity::{Algorithm, HashType, Parameters};
use std::num::NonZeroU64;

#[test]
fn defaults_and_explicit_parameters_build_without_hashing() {
    let parameters = Parameters::builder()
        .build(NonZeroU64::new(3).unwrap())
        .unwrap();
    assert_eq!(parameters.hash_type(), HashType::Normal);
    assert_eq!(parameters.algorithm(), Algorithm::Sha256);
    assert_eq!(parameters.data_block_size().get(), 4096);
    assert_eq!(parameters.hash_block_size().get(), 4096);
    assert_eq!(parameters.data_blocks().get(), 3);
    assert_eq!(parameters.salt(), []);

    let parameters = Parameters::builder()
        .hash_type(HashType::ChromeOs)
        .algorithm(Algorithm::Sha1)
        .data_block_size(512)
        .unwrap()
        .hash_block_size(1024)
        .unwrap()
        .salt(&[7; 257])
        .build(NonZeroU64::new(17).unwrap())
        .unwrap();
    let target = parameters
        .target(
            DevId::new(7, 0).unwrap(),
            DevId::new(7, 1).unwrap(),
            &[0; 20],
        )
        .unwrap();
    assert_eq!(target.parameters(), &parameters);
    assert_eq!(target.data_sectors(), 17);
    assert_eq!(parameters.hash_type(), HashType::ChromeOs);
    assert_eq!(parameters.algorithm(), Algorithm::Sha1);
    assert_eq!(parameters.hash_block_size().get(), 1024);
    assert_eq!(parameters.salt(), [7; 257]);
}

#[test]
fn setters_reject_invalid_sizes_immediately() {
    for size in [0, 1, 511, 513, 1 << 31, u32::MAX] {
        assert!(Parameters::builder().data_block_size(size).is_err());
        assert!(Parameters::builder().hash_block_size(size).is_err());
    }
    for size in [512, 4096, 512 * 1024, 1 << 30] {
        assert!(Parameters::builder().data_block_size(size).is_ok());
        assert!(Parameters::builder().hash_block_size(size).is_ok());
    }
}

#[test]
fn build_checks_layout_overflow() {
    assert!(
        Parameters::builder()
            .build(NonZeroU64::new(u64::MAX).unwrap())
            .is_err()
    );
}

#[test]
fn kernel_sector_extents_do_not_inherit_header_byte_limits() {
    let id = DevId::new(7, 0).unwrap();
    let parameters = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(u64::MAX).unwrap())
        .unwrap();
    let target = parameters.target(id, id, &[0; 32]).unwrap();
    assert_eq!(target.data_sectors(), u64::MAX);
    assert_eq!(
        target
            .to_string()
            .parse::<devmap_verity::dm::VerityTarget>()
            .unwrap(),
        target
    );
    assert!(target.with_hash_start_block(u64::MAX).is_err());
}

#[test]
fn kernel_parameters_are_not_limited_to_header_block_sizes() {
    let parameters = Parameters::builder()
        .data_block_size(1 << 30)
        .unwrap()
        .hash_block_size(1 << 30)
        .unwrap()
        .build(NonZeroU64::new(2).unwrap())
        .unwrap();
    let target = parameters
        .target(
            DevId::new(7, 0).unwrap(),
            DevId::new(7, 1).unwrap(),
            &[0; 32],
        )
        .unwrap();
    assert_eq!(
        target
            .to_string()
            .parse::<devmap_verity::dm::VerityTarget>()
            .unwrap(),
        target
    );
}

#[test]
fn target_options_validate_against_final_parameters() {
    let id = DevId::new(7, 0).unwrap();
    let parameters = Parameters::builder()
        .build(NonZeroU64::new(i32::MAX as u64 + 1).unwrap())
        .unwrap();
    let target = parameters.target(id, id, &[0; 32]).unwrap();
    assert!(target.clone().with_check_at_most_once(false).is_ok());
    assert!(target.with_check_at_most_once(true).is_err());

    let parameters = Parameters::builder().build(NonZeroU64::MIN).unwrap();
    let target = parameters.target(id, id, &[0; 32]).unwrap();
    assert!(target.clone().with_header_offset_bytes(u64::MAX).is_err());
    let fec = devmap_verity::dm::Fec::new(id, NonZeroU64::MIN, 2)
        .unwrap()
        .start(u64::MAX);
    assert!(target.with_fec(fec).is_err());
}
