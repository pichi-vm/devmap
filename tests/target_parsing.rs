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
    row::<devmap_delay::dm::Target>("7:0 0 10 7:1 1 20 7:2 2 30", &[3, 6]);
    row::<devmap_dust::dm::Target>("7:0 0 512", &[]);
    row::<devmap_era::dm::Target>("7:0 7:1 128", &[]);
    row::<devmap_flakey::dm::Target>("7:0 0 2 3 5 corrupt_bio_byte 1 r 2 0", &[]);
    row::<devmap_integrity::dm::Table>("7:0 0 16 J 1 buffer_sectors:128", &[]);
    row::<devmap_log_writes::dm::Target>("7:0 7:1", &[]);
    row::<devmap_raid::dm::Target>("raid1 1 0 2 - 7:0 - 7:1", &[]);
    row::<devmap_snapshot::dm::Target>("7:0 7:1 PO 32", &[]);
    row::<devmap_striped::dm::Target>("2 128 7:0 0 7:1 0", &[]);
    row::<devmap_thin::dm::Target>("7:0 1 7:1", &[2]);
    row::<devmap_thin_pool::dm::Target>("7:0 7:1 128 32 1 skip_block_zeroing", &[]);
    row::<devmap_unstriped::dm::Target>("2 128 0 7:0 0", &[]);
    row::<devmap_writecache::dm::Target>("s 7:0 7:1 4096 2 high_watermark 90", &[]);
    row::<devmap_zoned::dm::Target>("7:0", &[]);
}

#[test]
fn status_parsers_preserve_required_optional_and_trailing_fields() {
    row::<devmap_delay::dm::Info>("142 58 0", &[]);
    row::<devmap_dust::dm::Info>("7:0 bypass quiet", &[]);
    row::<devmap_era::dm::Info>("8 12/256 5 -", &[]);
    row::<devmap_integrity::dm::Info>("0 2097152 -", &[]);
    row::<devmap_log_writes::dm::Info>("12345 98303 logging_disabled", &[2]);
    row::<devmap_raid::dm::Info>("raid1 2 AD 12/64 idle 17 2048 A", &[]);
    row::<devmap_snapshot::dm::Info>("12/64 8", &[]);
    row::<devmap_striped::dm::Info>("2 7:0 7:1 1 AD", &[]);
    row::<devmap_thin::dm::Info>("32768 -", &[]);
    row::<devmap_thin_pool::dm::Info>(
        "7 64/256 4096/16384 - rw discard_passdown queue_if_no_space - 25 ",
        &[],
    );
    row::<devmap_verity::dm::Info>("V -", &[]);
    row::<devmap_writecache::dm::Info>(
        "0 65536 65000 12 10240 9800 51200 48000 2000 200 100 50 32 16",
        &[],
    );
    row::<devmap_zoned::dm::Info>(
        "4096 zones 0/0 cache 512/512 random 3584/3584 sequential",
        &[4],
    );
}

#[test]
fn malformed_optional_fields_are_not_treated_as_absent() {
    reject::<devmap_thin::dm::Target>(&["7:0 1 -", "7:0 1 bad", "7:0 1 7:1 7:2"]);
    reject::<devmap_crypt::dm::Target>(&[
        "aes-xts-plain64 - 0 7:0 0 bad",
        "aes-xts-plain64 - 0 7:0 0 1",
        "aes-xts-plain64 - 0 7:0 0 1 unknown",
    ]);
    reject::<devmap_log_writes::dm::Info>(&["1 2 unknown", "1 2 logging_disabled extra"]);
    reject::<devmap_era::dm::Info>(&["8 1/2 3 bad"]);
    reject::<devmap_integrity::dm::Info>(&["0 8 bad"]);
    reject::<devmap_verity::dm::Info>(&["V bad"]);
    reject::<devmap_raid::dm::Info>(&["raid1 2 AA 0/1 idle 0 0 AA"]);
}

#[test]
fn counted_options_require_exactly_the_declared_fields() {
    reject::<devmap_crypt::dm::Target>(&[
        "aes-xts-plain64 - 0 7:0 0 0 allow_discards",
        "aes-xts-plain64 - 0 7:0 0 2 allow_discards",
    ]);
    reject::<devmap_flakey::dm::Target>(&[
        "7:0 0 2 3 4 corrupt_bio_byte 1 r 2 0",
        "7:0 0 2 3 6 corrupt_bio_byte 1 r 2 0",
    ]);
    reject::<devmap_integrity::dm::Table>(&[
        "7:0 0 16 J 0 buffer_sectors:128",
        "7:0 0 16 J 2 buffer_sectors:128",
        "7:0 0 16 J 1 buffer_sectors",
        "7:0 0 16 J 1 buffer_sectors:4294967296",
    ]);
    reject::<devmap_raid::dm::Target>(&[
        "raid1 2 0 2 - 7:0 - 7:1",
        "raid1 1 0 1 - 7:0 - 7:1",
        "raid1 1 0 3 - 7:0 - 7:1",
    ]);
    reject::<devmap_striped::dm::Target>(&["1 128 7:0 0 7:1 0", "3 128 7:0 0 7:1 0"]);
    reject::<devmap_thin_pool::dm::Target>(&[
        "7:0 7:1 128 32 0 skip_block_zeroing",
        "7:0 7:1 128 32 2 skip_block_zeroing",
    ]);
    reject::<devmap_writecache::dm::Target>(&[
        "s 7:0 7:1 4096 1 high_watermark 90",
        "s 7:0 7:1 4096 3 high_watermark 90",
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
    for text in ["Fail", "Error", "-"] {
        row::<devmap_thin::dm::Info>(text, &[]);
    }
    row::<devmap_thin_pool::dm::Info>("Fail", &[]);
}

#[test]
fn usage_fields_do_not_gain_new_relationship_constraints() {
    row::<devmap_era::dm::Info>("8 12/8 0 -", &[]);
    row::<devmap_snapshot::dm::Info>("0/0 0", &[]);
    row::<devmap_raid::dm::Info>("raid1 1 A 12/8 idle 0 0 -", &[]);
    row::<devmap_thin_pool::dm::Info>(
        "0 0/0 12/8 - rw discard_passdown queue_if_no_space - 0 ",
        &[],
    );
    row::<devmap_zoned::dm::Info>("0 zones 0/0 cache 12/8 random 0/0 sequential", &[4]);
    reject::<devmap_era::dm::Info>(&["8 1/2/3 0 -"]);
    reject::<devmap_snapshot::dm::Info>(&["1/2/3 0"]);
    reject::<devmap_raid::dm::Info>(&["raid1 1 A 1/2/3 idle 0 0 -"]);
    reject::<devmap_thin_pool::dm::Info>(&[
        "0 1/2/3 0/0 - rw discard_passdown queue_if_no_space - 0",
    ]);
    reject::<devmap_zoned::dm::Info>(&["0 zones 1/2/3 cache"]);
}
