// SPDX-License-Identifier: Apache-2.0
use devmap_core::parse::{DevId, Empty, Error, Fraction};

#[test]
fn identifiers_round_trip_without_a_linux_dependency() {
    for (major, minor, encoded) in [(252, 5, 0xfc05), (1, 0x1_2345, 0x1230_0145)] {
        let id = DevId::new(major, minor).unwrap();
        assert_eq!(u64::from(id), encoded);
        assert_eq!(DevId::from(u32::try_from(encoded).unwrap()), id);
        assert_eq!(id.to_string().parse::<DevId>().unwrap(), id);
    }
    assert!(DevId::new(4096, 0).is_none());
    assert!(DevId::new(0, 1 << 20).is_none());
    for text in ["", "1", "1:2:3", "4096:0", "0:1048576"] {
        assert!(text.parse::<DevId>().is_err());
    }
}

#[test]
fn empty_status_rejects_unexpected_text() {
    assert!("".parse::<Empty>().is_ok());
    assert!(" \t\n".parse::<Empty>().is_ok());
    assert!("unexpected".parse::<Empty>().is_err());
}

#[test]
fn fractions_round_trip_without_interpreting_their_values() {
    for values in [(0, 0), (0, 1), (12, 8), (9, 10), (u32::MAX, u32::MAX)] {
        let fraction = Fraction::from(values);
        let text = fraction.to_string();
        assert_eq!(text, format!("{}/{}", values.0, values.1));
        assert_eq!(text.parse::<Fraction<u32>>().unwrap(), fraction);
        assert_eq!(<(u32, u32)>::from(fraction), values);
    }
    for values in [(0, 0), (12, 8), (u64::MAX, u64::MAX)] {
        let fraction = Fraction::from(values);
        let text = fraction.to_string();
        assert_eq!(text, format!("{}/{}", values.0, values.1));
        assert_eq!(text.parse::<Fraction<u64>>().unwrap(), fraction);
        assert_eq!(<(u64, u64)>::from(fraction), values);
    }
}

#[test]
fn integer_fractions_reject_malformed_fields_and_overflow() {
    for text in [
        "", "1", "/", "/1", "1/", "1/2/3", "x/2", "1/x", "-1/2", "1/-2", " 1/2", "1/2 ", "1 /2",
        "1/ 2", "1\n/2", "1/2\0",
    ] {
        assert_eq!(text.parse::<Fraction<u32>>(), Err(Error), "{text:?}");
        assert_eq!(text.parse::<Fraction<u64>>(), Err(Error), "{text:?}");
    }
    for text in ["4294967296/0", "0/4294967296"] {
        assert_eq!(text.parse::<Fraction<u32>>(), Err(Error));
        assert!(text.parse::<Fraction<u64>>().is_ok());
    }
    for text in ["18446744073709551616/0", "0/18446744073709551616"] {
        assert_eq!(text.parse::<Fraction<u64>>(), Err(Error));
    }
}

#[test]
fn fraction_components_use_their_own_parser_and_formatter() {
    let fraction: Fraction<u32> = "+0012/0064".parse().unwrap();
    assert_eq!(fraction.to_string(), "12/64");
    let signed: Fraction<i64> = "-3/0".parse().unwrap();
    assert_eq!(<(i64, i64)>::from(signed), (-3, 0));
}

#[cfg(target_os = "linux")]
#[test]
fn identifiers_reject_regular_files() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(
        DevId::from_path(file.path()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
