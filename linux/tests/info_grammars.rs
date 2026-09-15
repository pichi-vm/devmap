// SPDX-License-Identifier: Apache-2.0

//! Supported targets' `STATUSTYPE_INFO` grammar, parsed from a
//! kernel-realistic line and rendered back.
//!
//! These are pure parse tests — no ioctl, no root — kept in one file so
//! the fixture lines sit side by side and can be checked against the
//! kernel's `.status` callbacks as a set. Per-target behaviour that needs
//! a live device is covered by the other integration tests.
//!
//! Every fixture is the shape the kernel actually emits, taken from the
//! `STATUSTYPE_INFO` branch of each target's status callback.

use std::fmt::Display;
use std::str::FromStr;

use devmap_core::NoInfo;
use devmap_snapshot::dm as snapshot;
use devmap_verity::dm as verity;

/// Parse `line`, assert it renders back byte for byte, and hand back the
/// parsed value for field assertions. The round trip is what proves the
/// parser consumed the whole grammar rather than a prefix of it.
fn round_trip<T>(line: &str) -> T
where
    T: FromStr + Display,
    <T as FromStr>::Err: std::fmt::Debug,
{
    let parsed: T = line
        .parse()
        .unwrap_or_else(|e| panic!("parse {line:?}: {e:?}"));
    assert_eq!(parsed.to_string(), line, "must re-render exactly");
    parsed
}

#[test]
fn targets_with_no_runtime_status_accept_only_an_empty_line() {
    assert_eq!("".parse::<NoInfo>(), Ok(NoInfo));
    assert_eq!("   ".parse::<NoInfo>(), Ok(NoInfo));
    // A kernel that grew a status for one of these must not be silently
    // reported as "nothing to see".
    assert!("something".parse::<NoInfo>().is_err());
}

#[test]
fn verity_reports_corruption_and_fec() {
    let info: verity::Info = round_trip("V -");
    assert!(!info.corrupted);
    assert_eq!(info.fec_corrected, None);

    let info: verity::Info = round_trip("C 42");
    assert!(info.corrupted);
    assert_eq!(info.fec_corrected, Some(42));

    assert!("X -".parse::<verity::Info>().is_err());
}

#[test]
fn snapshot_reports_usage_or_a_state_keyword() {
    let info: snapshot::Info = round_trip("20480/524288 2048");
    assert_eq!(
        info,
        snapshot::Info::Usage {
            allocated_sectors: 20480,
            total_sectors: 524_288,
            metadata_sectors: 2048,
        }
    );

    // The keywords replace every numeric field, and "Merge failed" is two
    // tokens — which is why the parser matches the line before splitting.
    for (line, expected) in [
        ("Invalid", snapshot::Info::Invalid),
        ("Merge failed", snapshot::Info::MergeFailed),
        ("Overflow", snapshot::Info::Overflow),
        ("Unknown", snapshot::Info::Unknown),
    ] {
        assert_eq!(round_trip::<snapshot::Info>(line), expected);
    }
}
