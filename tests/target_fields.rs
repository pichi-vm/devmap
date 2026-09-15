// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use devmap_core::ParseError;

fn keywords<T: FromStr<Err = ParseError> + Display + Debug + PartialEq>(cases: &[(&str, T)]) {
    for (text, expected) in cases {
        assert_eq!(&text.parse::<T>().unwrap(), expected);
        assert_eq!(expected.to_string(), *text);
        for invalid in [
            format!(" {text}"),
            format!("{text} "),
            format!("{text} extra"),
        ] {
            assert_eq!(invalid.parse::<T>(), Err(ParseError), "{invalid:?}");
        }
    }
    for invalid in ["", "unknown", "☃"] {
        assert_eq!(invalid.parse::<T>(), Err(ParseError));
    }
}

#[test]
fn writecache_kinds_are_fields() {
    use devmap_writecache::dm::Kind;
    keywords(&[("s", Kind::Ssd), ("p", Kind::PersistentMemory)]);
}

#[test]
fn dust_modes_are_fields() {
    use devmap_dust::dm::{ReadBehavior, Verbosity};
    keywords(&[
        ("fail_read_on_bad_block", ReadBehavior::FailOnBadBlock),
        ("bypass", ReadBehavior::Bypass),
    ]);
    keywords(&[("verbose", Verbosity::Verbose), ("quiet", Verbosity::Quiet)]);
}

#[test]
fn flakey_directions_are_fields() {
    use devmap_flakey::dm::Direction;
    keywords(&[("r", Direction::Read), ("w", Direction::Write)]);
}

#[test]
fn integrity_modes_are_fields() {
    use devmap_integrity::dm::Mode;
    keywords(&[
        ("D", Mode::Direct),
        ("J", Mode::Journaled),
        ("B", Mode::Bitmap),
        ("R", Mode::Recovery),
        ("I", Mode::Inline),
    ]);
}

#[test]
fn raid_personalities_and_actions_are_fields() {
    use devmap_raid::dm::{SyncAction, Type};
    keywords(&[
        ("raid0", Type::Raid0),
        ("raid1", Type::Raid1),
        ("raid4", Type::Raid4),
        ("raid5_ls", Type::Raid5),
        ("raid6_zr", Type::Raid6),
        ("raid10", Type::Raid10),
    ]);
    for unsupported in ["raid5", "raid6", "raid5_ra", "raid6_nc"] {
        assert_eq!(unsupported.parse::<Type>(), Err(ParseError));
    }
    keywords(&[
        ("frozen", SyncAction::Frozen),
        ("reshape", SyncAction::Reshape),
        ("resync", SyncAction::Resync),
        ("check", SyncAction::Check),
        ("repair", SyncAction::Repair),
        ("recover", SyncAction::Recover),
        ("idle", SyncAction::Idle),
        ("undef", SyncAction::Undef),
    ]);
}

#[test]
fn raid_health_accepts_exactly_one_character() {
    use devmap_raid::dm::DeviceHealth;
    let cases = [
        ("A", DeviceHealth::InSync),
        ("a", DeviceHealth::OutOfSync),
        ("D", DeviceHealth::Dead),
        ("-", DeviceHealth::Missing),
    ];
    keywords(&cases);
    for (text, expected) in cases {
        assert_eq!(
            DeviceHealth::try_from(text.chars().next().unwrap()),
            Ok(expected)
        );
    }
    for invalid in ["AA", "Aa", "--", "d"] {
        assert_eq!(invalid.parse::<DeviceHealth>(), Err(ParseError));
    }
    assert_eq!(DeviceHealth::try_from('x'), Err(ParseError));
}

#[test]
fn thin_pool_modes_are_fields() {
    use devmap_thin_pool::dm::{AccessMode, DiscardMode, OutOfSpacePolicy};
    keywords(&[
        ("rw", AccessMode::ReadWrite),
        ("ro", AccessMode::ReadOnly),
        ("out_of_data_space", AccessMode::OutOfDataSpace),
    ]);
    keywords(&[
        ("ignore_discard", DiscardMode::Ignore),
        ("discard_passdown", DiscardMode::Passdown),
        ("no_discard_passdown", DiscardMode::NoPassdown),
    ]);
    keywords(&[
        ("error_if_no_space", OutOfSpacePolicy::Error),
        ("queue_if_no_space", OutOfSpacePolicy::Queue),
    ]);
}

#[test]
fn stripe_health_accepts_exactly_one_character() {
    use devmap_striped::dm::StripeHealth;
    keywords(&[("A", StripeHealth::Alive), ("D", StripeHealth::Dead)]);
    assert_eq!(StripeHealth::try_from('A'), Ok(StripeHealth::Alive));
    assert_eq!(StripeHealth::try_from('D'), Ok(StripeHealth::Dead));
    for invalid in ["a", "-", "AA", "AD"] {
        assert_eq!(invalid.parse::<StripeHealth>(), Err(ParseError));
    }
    assert_eq!(StripeHealth::try_from('x'), Err(ParseError));
}

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
fn zoned_usage_preserves_counts_without_interpreting_them() {
    use devmap_zoned::dm::ZoneUsage;
    for (text, unmapped, total) in [
        ("0/0", 0, 0),
        ("12/8", 12, 8),
        ("4294967295/4294967295", u32::MAX, u32::MAX),
    ] {
        let value: ZoneUsage = text.parse().unwrap();
        assert_eq!(value.unmapped, unmapped);
        assert_eq!(value.total, total);
        assert_eq!(value.to_string(), text);
    }
    for invalid in [
        "",
        "1",
        "1/",
        "/1",
        "1/2/3",
        "x/1",
        "1/x",
        "4294967296/0",
        "0/4294967296",
    ] {
        assert_eq!(invalid.parse::<ZoneUsage>(), Err(ParseError));
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
