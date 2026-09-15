// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use devmap_core::ParseError;

fn row<T: FromStr<Err = ParseError> + Display + Debug + PartialEq>(
    text: &str,
    allowed_prefixes: &[usize],
) {
    let parsed: T = text.parse().unwrap();
    assert_eq!(parsed.to_string(), text);
    let fields: Vec<_> = text.split_whitespace().collect();
    for length in 0..fields.len() {
        let prefix = fields[..length].join(" ");
        assert_eq!(
            prefix.parse::<T>().is_ok(),
            allowed_prefixes.contains(&length),
            "prefix {prefix:?} of {text:?}"
        );
    }
    assert_eq!(format!("{text} unexpected").parse::<T>(), Err(ParseError));
    assert_eq!(
        format!(" \t{}\n", fields.join("\t")).parse::<T>(),
        Ok(parsed)
    );
}

fn reject<T: FromStr<Err = ParseError>>(cases: &[&str]) {
    for text in cases {
        assert!(
            text.parse::<T>().is_err(),
            "accepted malformed row {text:?}"
        );
    }
}

#[test]
fn table_parsers_preserve_required_optional_and_trailing_fields() {
    row::<devmap_crypt::dm::Target>(
        "aes-xts-plain64 :64:logon:example:volume 0 7:0 0 1 allow_discards",
        &[5],
    );
    row::<devmap_snapshot::dm::Target>("7:0 7:1 PO 32", &[]);
}

#[test]
fn status_parsers_preserve_required_optional_and_trailing_fields() {
    row::<devmap_snapshot::dm::Info>("12/64 8", &[]);
    row::<devmap_verity::dm::Info>("V -", &[]);
}

#[test]
fn malformed_optional_fields_are_not_treated_as_absent() {
    reject::<devmap_crypt::dm::Target>(&[
        "aes-xts-plain64 - 0 7:0 0 bad",
        "aes-xts-plain64 - 0 7:0 0 1",
        "aes-xts-plain64 - 0 7:0 0 1 unknown",
    ]);
    reject::<devmap_verity::dm::Info>(&["V bad"]);
}

#[test]
fn counted_options_require_exactly_the_declared_fields() {
    reject::<devmap_crypt::dm::Target>(&[
        "aes-xts-plain64 - 0 7:0 0 0 allow_discards",
        "aes-xts-plain64 - 0 7:0 0 2 allow_discards",
    ]);
}

#[test]
fn special_statuses_remain_whole_row_alternatives() {
    for text in ["Invalid", "Overflow", "Unknown"] {
        row::<devmap_snapshot::dm::Info>(text, &[]);
    }
    let merge: devmap_snapshot::dm::Info = " Merge failed ".parse().unwrap();
    assert_eq!(merge, devmap_snapshot::dm::Info::MergeFailed);
    assert_eq!(merge.to_string(), "Merge failed");
    reject::<devmap_snapshot::dm::Info>(&["Merge", "Merge failed extra"]);
}

#[test]
fn usage_fields_do_not_gain_new_relationship_constraints() {
    row::<devmap_snapshot::dm::Info>("0/0 0", &[]);
    reject::<devmap_snapshot::dm::Info>(&["1/2/3 0"]);
}
