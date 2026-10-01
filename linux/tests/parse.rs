// SPDX-License-Identifier: Apache-2.0
use devmap_linux::{
    DevId,
    table::{InfoMode, TableMode},
    target::Parse,
    target::{Empty, Version},
};

#[test]
fn identifiers_round_trip() {
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

    let version = Version::from([1, 0, 0]);
    assert_eq!(<Empty as Parse<TableMode>>::parse("", version), Ok(Empty));
    assert_eq!(<Empty as Parse<InfoMode>>::parse("", version), Ok(Empty));
}

#[cfg(target_os = "linux")]
#[test]
fn identifiers_reject_regular_files() {
    assert_eq!(
        DevId::try_from(std::fs::metadata(std::env::current_exe().unwrap()).unwrap())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(
        DevId::try_from(file).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
