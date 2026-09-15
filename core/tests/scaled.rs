// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Cursor, Read as _, Seek as _, Write as _};
use std::num::NonZeroU32;

use devmap_core::traits::std::*;

#[test]
fn scale_preserves_extent_and_forwards_io() {
    let mut device = Cursor::new(vec![0; 16])
        .scale(NonZeroU32::new(4).unwrap())
        .unwrap();

    assert_eq!(device.block_size().unwrap().get(), 4);
    assert_eq!(device.count().unwrap(), 4);
    device.write_all(&[1, 2, 3]).unwrap();
    device.rewind().unwrap();
    let mut bytes = [0; 3];
    device.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [1, 2, 3]);
    device.sync_data().unwrap();
}

#[test]
fn scale_rejects_incoherent_geometry() {
    let error = Cursor::new(vec![0; 16])
        .scale(NonZeroU32::new(3).unwrap())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let error = Cursor::new(vec![0; 15])
        .scale(NonZeroU32::new(4).unwrap())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

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
