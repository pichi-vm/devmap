// SPDX-License-Identifier: Apache-2.0
use devmap_core::traits::std::{Geometry as _, Scale as _, SliceBytes as _};
use std::io::{self, Cursor, Read as _, Seek as _, SeekFrom};
use std::num::NonZeroU32;

#[test]
fn scale_to_uses_bytes_and_preserves_position_and_extent() {
    let mut bytes = Cursor::new(vec![0; 8192]);
    bytes.set_position(19);
    let mut device = bytes
        .scale_to(NonZeroU32::new(512).unwrap())
        .unwrap()
        .scale_to(NonZeroU32::new(4096).unwrap())
        .unwrap();
    assert_eq!(device.block_size().unwrap().get(), 4096);
    assert_eq!(device.count().unwrap(), 2);
    assert_eq!(device.stream_position().unwrap(), 19);
    assert_eq!(
        device
            .scale_to(NonZeroU32::new(4096).unwrap())
            .unwrap()
            .block_size()
            .unwrap()
            .get(),
        4096
    );
}

#[test]
fn scale_to_rejects_rounding_shrinking_and_partial_blocks() {
    for requested in [1, 256, 513, 1536] {
        let device = Cursor::new(vec![0; 8192])
            .scale_to(NonZeroU32::new(512).unwrap())
            .unwrap();
        assert_eq!(
            device
                .scale_to(NonZeroU32::new(requested).unwrap())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(
        Cursor::new(vec![0; 513])
            .scale_to(NonZeroU32::new(512).unwrap())
            .is_err()
    );
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
