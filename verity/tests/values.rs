// SPDX-License-Identifier: Apache-2.0

use devmap_core::parse::DevId;
use devmap_verity::{
    Algorithm, BlockSize, Fec, HashType, KeyDescription, Options, Scheme, Shape, VerityTarget,
};
use std::num::{NonZeroU32, NonZeroU64};

#[test]
fn values_are_copy_and_defaults_are_independent() {
    fn copy<T: Copy>() {}
    copy::<Scheme>();
    copy::<Shape>();
    copy::<Options<'_>>();
    copy::<Fec>();
    let scheme = Scheme::default();
    assert_eq!(scheme.hash_type, HashType::Normal);
    assert_eq!(scheme.algorithm, Algorithm::Sha256);
    assert_eq!(scheme.salt.as_slice(), []);
    let shape = Shape::new(NonZeroU64::new(3).unwrap());
    assert_eq!(u32::from(shape.data_block_size), 4096);
    assert_eq!(u32::from(shape.hash_block_size), 4096);
    assert_eq!(shape.data_blocks.get(), 3);
    let changed = scheme
        .with_algorithm(Algorithm::Sha1)
        .with_salt(&[7; 256])
        .unwrap();
    assert_eq!(changed.salt.len(), 256);
    assert_eq!(scheme.salt.len(), 0);
    assert!(scheme.with_salt(&[7; 257]).is_err());
    assert_eq!(changed.with_salt(&[]).unwrap().salt.as_slice(), []);
}

#[test]
fn block_sizes_validate_and_convert_in_bytes() {
    for size in [0u32, 1, 511, 513, 1 << 31, u32::MAX] {
        assert!(BlockSize::try_from(size).is_err());
        assert!(size.to_string().parse::<BlockSize>().is_err());
    }
    for size in [512u32, 4096, 512 * 1024, 1 << 30] {
        let value = BlockSize::try_from(size).unwrap();
        assert_eq!(u32::from(value), size);
        assert_eq!(NonZeroU32::from(value).get(), size);
        assert_eq!(
            BlockSize::try_from(NonZeroU32::new(size).unwrap()).unwrap(),
            value
        );
        assert_eq!(value.to_string().parse::<BlockSize>().unwrap(), value);
    }
}

#[test]
fn combinations_are_validated_at_target_construction_not_stored_in_values() {
    let id = DevId::new(7, 0).unwrap();
    let mut shape = Shape::new(NonZeroU64::new(u64::MAX).unwrap());
    assert!(
        Options::default()
            .target(Scheme::default(), shape, id, id, &[0; 32])
            .is_err()
    );
    shape.data_block_size = 512u32.try_into().unwrap();
    shape.hash_block_size = 512u32.try_into().unwrap();
    let target = Options::default()
        .target(Scheme::default(), shape, id, id, &[0; 32])
        .unwrap();
    assert_eq!(target.data_sectors(), u64::MAX);
    assert_eq!(target.to_string().parse::<VerityTarget>().unwrap(), target);
    let options = Options::default().with_hash_start_block(u64::MAX);
    assert!(
        options
            .target(Scheme::default(), shape, id, id, &[0; 32])
            .is_err()
    );
    let large = Shape::new(NonZeroU64::new(2).unwrap())
        .with_data_block_size((1u32 << 30).try_into().unwrap())
        .with_hash_block_size((1u32 << 30).try_into().unwrap());
    assert!(
        Options::default()
            .target(Scheme::default(), large, id, id, &[0; 32])
            .is_ok()
    );
}

#[test]
fn accepted_targets_do_not_borrow_mutable_inputs_or_signature_text() {
    let id = DevId::new(7, 0).unwrap();
    let mut shape = Shape::new(NonZeroU64::MIN);
    let target = {
        let key = String::from("signature with spaces");
        let options = Options::default()
            .with_root_hash_sig_key_desc(KeyDescription::try_from(key.as_str()).unwrap());
        options
            .target(Scheme::default(), shape, id, id, &[0; 32])
            .unwrap()
    };
    shape.data_blocks = NonZeroU64::new(2).unwrap();
    assert_ne!(target.shape(), shape);
    assert_eq!(
        target.options().root_hash_sig_key_desc.unwrap().as_ref(),
        "signature with spaces"
    );
    assert_eq!(target.to_string().parse::<VerityTarget>().unwrap(), target);
    for invalid in ["", "bad\0key"] {
        assert!(KeyDescription::try_from(invalid).is_err());
    }
}

#[test]
fn options_validate_fec_and_first_read_only_limits() {
    let id = DevId::new(7, 0).unwrap();
    let shape = Shape::new(NonZeroU64::new(i32::MAX as u64 + 1).unwrap());
    assert!(
        Options::default()
            .with_check_at_most_once(true)
            .target(Scheme::default(), shape, id, id, &[0; 32])
            .is_err()
    );
    let fec = Fec::new(id, NonZeroU64::MIN, 2).unwrap().start(u64::MAX);
    assert!(
        Options::default()
            .with_fec(fec)
            .target(
                Scheme::default(),
                Shape::new(NonZeroU64::MIN),
                id,
                id,
                &[0; 32]
            )
            .is_err()
    );
}
