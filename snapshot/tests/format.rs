// SPDX-License-Identifier: Apache-2.0

use devmap_snapshot::Formatter;
use std::num::NonZeroU32;

#[test]
fn capacity_includes_metadata_and_exact_area_terminators() {
    let format = Formatter::new(NonZeroU32::new(8).unwrap()).unwrap();
    assert_eq!(format.required_size(0, NonZeroU32::MIN).unwrap(), 8192);
    assert_eq!(
        format.required_size(256 * 4096, NonZeroU32::MIN).unwrap(),
        259 * 4096
    );
    assert!(
        format
            .required_size(4096, NonZeroU32::new(65536).unwrap())
            .is_err()
    );
    assert!(format.required_size(u64::MAX, NonZeroU32::MIN).is_err());
}

#[test]
fn creation_formats_metadata_without_copying_the_origin() {
    use devmap_snapshot::{
        Layer,
        traits::std::{Create as _, Open as _, SyncData as _},
    };
    use std::io::{Cursor, Read as _};

    let mut origin = Cursor::new(vec![0x55; 4 * 4096 + 17]);
    let mut cow = Cursor::new(vec![0xcc; 7 * 4096]);
    let mut layer = Layer::create(&mut origin, &mut cow, NonZeroU32::new(8).unwrap()).unwrap();
    layer.sync_data().unwrap();
    drop(layer);

    let mut expected = vec![0; 2 * 4096];
    expected[..16].copy_from_slice(&[0x53, 0x6e, 0x41, 0x70, 1, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0]);
    assert_eq!(&cow.get_ref()[..2 * 4096], expected);
    assert!(cow.get_ref()[2 * 4096..].iter().all(|byte| *byte == 0xcc));

    let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
    let mut actual = Vec::new();
    layer.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, vec![0x55; 4 * 4096 + 17]);
}
