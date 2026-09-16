// SPDX-License-Identifier: Apache-2.0

use devmap_core::BlockSize;
use std::{io, num::NonZeroU32};

#[test]
fn sizes_validate_and_convert_in_bytes() {
    for size in [0u32, 1, 511, 513, 1 << 31, u32::MAX] {
        assert_eq!(
            BlockSize::<512>::try_from(size).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(size.to_string().parse::<BlockSize>().is_err());
        if let Some(size) = NonZeroU32::new(size) {
            assert!(BlockSize::<512>::try_from(size).is_err());
        }
    }
    for exponent in 9..=30 {
        let size = 1u32 << exponent;
        let value = BlockSize::<512>::try_from(size).unwrap();
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
    let size: BlockSize = BlockSize::default();
    assert_eq!(u32::from(size), 4096);
    assert!(BlockSize::try_from(512u32).unwrap() < size);
}

fn check_minimum<const MIN: u32>() {
    for bytes in [
        0u32,
        1,
        2,
        3,
        4,
        8,
        511,
        512,
        513,
        1024,
        4096,
        8192,
        1 << 30,
        1 << 31,
    ] {
        let valid = bytes != 0 && bytes.is_power_of_two() && bytes >= MIN && bytes <= 1 << 30;
        let parsed = BlockSize::<MIN>::try_from(bytes);
        assert_eq!(parsed.is_ok(), valid, "minimum {MIN}, size {bytes}");
        assert_eq!(bytes.to_string().parse::<BlockSize<MIN>>().is_ok(), valid);
        if let Some(bytes) = NonZeroU32::new(bytes) {
            assert_eq!(BlockSize::<MIN>::try_from(bytes).is_ok(), valid);
        }
        if let Ok(size) = parsed {
            assert_eq!(u32::from(size), bytes);
            assert_eq!(NonZeroU32::from(size).get(), bytes);
            assert_eq!(size.to_string().parse::<BlockSize<MIN>>().unwrap(), size);
        }
    }
}

#[test]
fn minimum_is_a_lower_bound_not_a_required_block_size() {
    check_minimum::<0>();
    check_minimum::<1>();
    check_minimum::<3>();
    check_minimum::<512>();
    check_minimum::<513>();
    check_minimum::<4096>();
    check_minimum::<8192>();
    check_minimum::<{ 1 << 30 }>();
    check_minimum::<{ (1 << 30) + 1 }>();
    check_minimum::<{ u32::MAX }>();
}

fn check_default<const MIN: u32>(expected: u32) {
    let size = BlockSize::<MIN>::default();
    assert_eq!(u32::from(size), expected);
    assert_eq!(BlockSize::<MIN>::try_from(expected).unwrap(), size);
}

#[test]
fn defaults_satisfy_the_minimum_without_rounding_below_it() {
    check_default::<0>(4096);
    check_default::<1>(4096);
    check_default::<512>(4096);
    check_default::<4096>(4096);
    check_default::<4097>(8192);
    check_default::<8192>(8192);
    check_default::<10000>(16384);
    check_default::<{ 1 << 30 }>(1 << 30);
}

#[test]
fn byte_sized_blocks_convert_to_stream_geometry() {
    use devmap_core::traits::std::{Geometry as _, Scale as _};
    let size = BlockSize::<1>::try_from(1u32).unwrap();
    let mut stream = std::io::Cursor::new(vec![1, 2, 3])
        .scale_to(size.into())
        .unwrap();
    assert_eq!(stream.block_size().unwrap().get(), 1);
    assert_eq!(stream.count().unwrap(), 3);
}
