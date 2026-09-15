// SPDX-License-Identifier: Apache-2.0

use devmap_core::ParseError;

#[test]
fn crypt_integrity_fields_preserve_the_kind() {
    use devmap_crypt::dm::Integrity;
    for (text, tag_size, kind) in [
        ("16:aead", 16, "aead"),
        ("0:", 0, ""),
        ("4294967295:future:kind", u32::MAX, "future:kind"),
    ] {
        let parsed: Integrity = text.parse().unwrap();
        assert_eq!(parsed.tag_size, tag_size);
        assert_eq!(parsed.kind, kind);
        assert_eq!(parsed.to_string(), text);
    }
    for invalid in ["", "16", ":aead", "x:aead", "4294967296:aead"] {
        assert_eq!(invalid.parse::<Integrity>(), Err(ParseError));
    }
}

#[test]
fn crypt_keys_parse_without_a_complete_target() {
    use devmap_crypt::dm::{Key, KeyType};
    assert_eq!("-".parse::<Key>(), Ok(Key::Absent));
    assert_eq!("aAbB01".parse::<Key>(), Ok(Key::Hex(vec![0xaa, 0xbb, 1])));
    assert_eq!("aAbB01".parse::<Key>().unwrap().to_string(), "aabb01");
    for (name, kind) in [
        ("logon", KeyType::Logon),
        ("user", KeyType::User),
        ("encrypted", KeyType::Encrypted),
        ("trusted", KeyType::Trusted),
    ] {
        let text = format!(":64:{name}:example:volume");
        let parsed: Key = text.parse().unwrap();
        assert_eq!(
            parsed,
            Key::Keyring {
                size: 64,
                kind,
                description: "example:volume".into()
            }
        );
        assert_eq!(parsed.to_string(), text);
    }
    for invalid in [
        "",
        "a",
        "xz",
        ":",
        ":64:logon",
        ":64:logon:",
        ":x:logon:key",
        ":4294967296:logon:key",
        ":64:unknown:key",
        "€0",
        "0€",
        "☃☃",
        "é",
    ] {
        assert_eq!(invalid.parse::<Key>(), Err(ParseError), "{invalid:?}");
    }
}

#[test]
fn malformed_unicode_keys_fail_the_complete_crypt_parser_without_panicking() {
    use devmap_crypt::dm::Target;
    for key in ["€0", "0€", "☃☃"] {
        let text = format!("aes-xts-plain64 {key} 0 7:0 0");
        assert_eq!(text.parse::<Target>(), Err(ParseError));
    }
}
