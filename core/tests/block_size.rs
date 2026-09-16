// SPDX-License-Identifier: Apache-2.0

use devmap_core::BlockSize;
use std::{io, num::NonZeroU32};

#[test]
fn sizes_validate_and_convert_in_bytes() {
    for size in [0u32, 1, 511, 513, 1 << 31, u32::MAX] {
        assert_eq!(
            BlockSize::try_from(size).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(size.to_string().parse::<BlockSize>().is_err());
        if let Some(size) = NonZeroU32::new(size) {
            assert!(BlockSize::try_from(size).is_err());
        }
    }
    for exponent in 9..=30 {
        let size = 1u32 << exponent;
        let value = BlockSize::try_from(size).unwrap();
        assert_eq!(u32::from(value), size);
        assert_eq!(NonZeroU32::from(value).get(), size);
        assert_eq!(
            BlockSize::try_from(NonZeroU32::new(size).unwrap()).unwrap(),
            value
        );
        assert_eq!(value.to_string(), size.to_string());
        assert_eq!(value.to_string().parse::<BlockSize>().unwrap(), value);
    }
    for invalid in ["", "-512", "4KiB", "4294967296"] {
        assert!(invalid.parse::<BlockSize>().is_err());
    }
}

#[test]
fn block_sizes_are_copyable_and_default_to_4096_bytes() {
    fn copy<T: Copy>() {}
    copy::<BlockSize>();
    let size = BlockSize::default();
    assert_eq!(u32::from(size), 4096);
    assert!(BlockSize::try_from(512u32).unwrap() < size);
}
