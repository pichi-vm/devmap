// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Cursor, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU32;

use devmap_core::traits::std::*;

#[test]
fn slice_maps_a_block_range_to_a_zero_based_device() {
    let source = Cursor::new((0_u8..16).collect::<Vec<_>>())
        .scale(NonZeroU32::new(2).unwrap())
        .unwrap();
    let mut device = source.slice(2..5).unwrap();

    assert_eq!(device.block_size().unwrap().get(), 2);
    assert_eq!(device.count().unwrap(), 3);
    let mut bytes = Vec::new();
    device.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [4, 5, 6, 7, 8, 9]);
    assert_eq!(device.seek(SeekFrom::Start(0)).unwrap(), 0);
    assert_eq!(device.as_mut().stream_position().unwrap(), 4);
}

#[test]
fn slice_accepts_a_start_count_pair_and_every_standard_range_form() {
    let mut region = Cursor::new(vec![0; 8]).slice(..).unwrap();
    assert_eq!(region.count().unwrap(), 8);

    let mut region = Cursor::new(vec![0; 8]).slice(..3).unwrap();
    assert_eq!(region.count().unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(..=3).unwrap();
    assert_eq!(region.count().unwrap(), 4);

    let mut region = Cursor::new(vec![0; 8]).slice(3..).unwrap();
    assert_eq!(region.count().unwrap(), 5);

    let mut region = Cursor::new(vec![0; 8]).slice(2..=4).unwrap();
    assert_eq!(region.count().unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice((2, 3)).unwrap();
    assert_eq!(region.count().unwrap(), 3);
}

#[test]
fn slice_rejects_invalid_ranges_and_limits_writes() {
    let error = Cursor::new(vec![0; 8])
        .slice(std::hint::black_box(5)..4)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let error = Cursor::new(vec![0; 8]).slice(7..9).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let error = Cursor::new(vec![0; 8]).slice((u64::MAX, 1)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut device = Cursor::new(vec![0; 8]).slice(2..4).unwrap();
    assert_eq!(device.write(&[1, 2, 3]).unwrap(), 2);
    assert_eq!(device.write(&[4]).unwrap(), 0);
    assert_eq!(device.into_inner().into_inner(), [0, 0, 1, 2, 0, 0, 0, 0]);
}

#[test]
fn byte_slices_check_alignment_and_translate_every_range() {
    let make = || {
        Cursor::new((0u8..16).collect::<Vec<_>>())
            .scale_to(NonZeroU32::new(4).unwrap())
            .unwrap()
    };
    let mut slices = [
        make().slice_bytes(4..12).unwrap(),
        make().slice_bytes(4..=11).unwrap(),
        make().slice_bytes((4, 8)).unwrap(),
    ];
    for slice in &mut slices {
        assert_eq!(slice.count().unwrap(), 2);
        assert_eq!(slice.seek(SeekFrom::Start(0)).unwrap(), 0);
        let mut bytes = Vec::new();
        slice.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, (4u8..12).collect::<Vec<_>>());
    }
    assert_eq!(make().slice_bytes(..).unwrap().count().unwrap(), 4);
    assert_eq!(make().slice_bytes(..8).unwrap().count().unwrap(), 2);
    assert_eq!(make().slice_bytes(..=7).unwrap().count().unwrap(), 2);
    assert_eq!(make().slice_bytes(8..).unwrap().count().unwrap(), 2);
    for range in [1..4, 4..5, 16..20, std::hint::black_box(8)..4] {
        assert_eq!(
            make().slice_bytes(range).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(make().slice_bytes(..=u64::MAX).is_err());
    assert!(make().slice_bytes((u64::MAX, 1)).is_err());
}
