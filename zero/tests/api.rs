// SPDX-License-Identifier: Apache-2.0

use devmap_core::traits::std::Geometry as _;
use devmap_zero::Zero;
use std::io::{Read as _, Seek as _, SeekFrom};

#[test]
fn zero_is_a_fixed_length_seekable_device() {
    let mut zero = Zero::new(17);
    assert_eq!(zero.block_size().unwrap().get(), 1);
    assert_eq!(zero.count().unwrap(), 17);

    zero.seek(SeekFrom::Start(11)).unwrap();
    let mut bytes = [0xff; 8];
    assert_eq!(zero.read(&mut bytes).unwrap(), 6);
    assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0xff, 0xff]);
    assert_eq!(zero.seek(SeekFrom::End(-2)).unwrap(), 15);
    assert_eq!(
        zero.seek(SeekFrom::Current(-16)).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
