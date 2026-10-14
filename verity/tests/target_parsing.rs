// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

use std::io::ErrorKind;

use devmap_linux::targets::{Parse, Version};
use devmap_verity::target::Verity;

const VERSION: Version = Version {
    major: 1,
    minor: 13,
    patch: 0,
};

#[test]
fn hex_tokens_are_unescaped_exactly_once() {
    let root = "ab".repeat(32);
    let expected = Verity::parse(
        &format!("1 7:0 7:1 4096 4096 1 0 sha256 {root} ab"),
        VERSION,
    )
    .unwrap();
    let escaped = format!(r"1 7:0 7:1 4096 4096 1 0 sha256 \{root} \ab");
    assert_eq!(Verity::parse(&escaped, VERSION).unwrap(), expected);
    for (digest, salt) in [
        (format!(r"\\{root}"), "ab".to_owned()),
        (root, r"\\ab".to_owned()),
    ] {
        let text = format!("1 7:0 7:1 4096 4096 1 0 sha256 {digest} {salt}");
        assert_eq!(
            Verity::parse(&text, VERSION).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
}

#[test]
fn malformed_table_parameters_are_invalid_data() {
    let root = "ab".repeat(32);
    let base = format!("1 7:0 7:1 4096 4096 1 0 sha256 {root} -");
    let mut cases = Vec::new();
    for (index, name, replacement) in [
        (0, "unknown hash type", "2"),
        (7, "unknown algorithm", "unknown"),
        (8, "non-hex root", "gg"),
        (8, "odd root length", "abc"),
        (9, "non-hex salt", "gg"),
        (9, "odd salt length", "abc"),
    ] {
        let mut fields: Vec<_> = base.split_whitespace().collect();
        fields[index] = replacement;
        cases.push((name, fields.join(" ")));
    }
    cases.push((
        "overlong salt",
        format!("{} {}", base.trim_end_matches('-'), "ab".repeat(257)),
    ));
    for (name, suffix) in [
        ("wrong option count", "2 ignore_zero_blocks"),
        ("invalid option count", "x ignore_zero_blocks"),
        ("missing signature value", "1 root_hash_sig_key_desc"),
        (
            "conflicting corruption policies",
            "2 ignore_corruption restart_on_corruption",
        ),
        (
            "conflicting I/O policies",
            "2 restart_on_error panic_on_error",
        ),
        ("unknown option", "1 unknown"),
        (
            "duplicate signature",
            "4 root_hash_sig_key_desc a root_hash_sig_key_desc b",
        ),
    ] {
        cases.push((name, format!("{base} {suffix}")));
    }
    assert!(Verity::parse(&base, VERSION).is_ok());
    for (name, text) in cases {
        assert_eq!(
            Verity::parse(&text, VERSION).unwrap_err().kind(),
            ErrorKind::InvalidData,
            "{name}"
        );
    }
}
