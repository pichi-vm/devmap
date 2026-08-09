// SPDX-License-Identifier: Apache-2.0

//! Every target's `STATUSTYPE_INFO` grammar, parsed from a
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

use devmap_linux::targets::{
    delay, dust, era, integrity, log_writes, raid, snapshot, striped, thin, thin_pool, verity,
    writecache, zoned,
};
use devmap_linux::{DevId, NoInfo};

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
fn delay_reports_per_direction_counters() {
    let info: delay::Info = round_trip("142 58 0");
    assert_eq!(info.read_ops, 142);
    assert_eq!(info.write_ops, 58);
    assert_eq!(info.flush_ops, 0);
}

#[test]
fn dust_reports_its_message_driven_mode() {
    let info: dust::Info = round_trip("7:0 fail_read_on_bad_block verbose");
    assert_eq!(info.device, DevId::new(7, 0).unwrap());
    assert_eq!(info.read_behavior, dust::ReadBehavior::FailOnBadBlock);
    assert_eq!(info.verbosity, dust::Verbosity::Verbose);

    let info: dust::Info = round_trip("7:0 bypass quiet");
    assert_eq!(info.read_behavior, dust::ReadBehavior::Bypass);
    assert_eq!(info.verbosity, dust::Verbosity::Quiet);

    assert!("7:0 bypass loud".parse::<dust::Info>().is_err());
}

#[test]
fn log_writes_reports_the_optional_disabled_keyword() {
    let info: log_writes::Info = round_trip("12345 98303");
    assert_eq!(info.logged_entries, 12345);
    assert_eq!(info.highest_sector, 98303);
    assert!(!info.logging_disabled);

    let info: log_writes::Info = round_trip("12345 98303 logging_disabled");
    assert!(info.logging_disabled);

    assert!("1 2 something_else".parse::<log_writes::Info>().is_err());
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
fn integrity_reports_mismatches_and_recalculation() {
    let info: integrity::Info = round_trip("0 2097152 -");
    assert_eq!(info.mismatches, 0);
    assert_eq!(info.provided_data_sectors, 2_097_152);
    assert_eq!(info.recalc_sector, None);

    let info: integrity::Info = round_trip("3 2097152 524288");
    assert_eq!(info.mismatches, 3);
    assert_eq!(info.recalc_sector, Some(524_288));
}

#[test]
fn era_reports_metadata_usage_and_the_current_era() {
    let info: era::Info = round_trip("8 12/256 5 -");
    assert_eq!(info.metadata_block_size_sectors, 8);
    assert_eq!(info.used_metadata_blocks, 12);
    assert_eq!(info.total_metadata_blocks, 256);
    assert_eq!(info.current_era, 5);
    assert_eq!(info.held_metadata_root, None);

    let info: era::Info = round_trip("8 12/256 5 4096");
    assert_eq!(info.held_metadata_root, Some(4096));
}

#[test]
fn striped_pairs_each_device_with_its_health() {
    let info: striped::Info = round_trip("3 7:0 7:1 7:2 1 AAD");
    assert_eq!(info.stripes.len(), 3);
    assert_eq!(info.stripes[0].0, DevId::new(7, 0).unwrap());
    assert_eq!(info.stripes[0].1, striped::StripeHealth::Alive);
    assert_eq!(info.stripes[2].1, striped::StripeHealth::Dead);
}

#[test]
fn striped_rejects_a_health_run_that_disagrees_with_the_count() {
    // The health characters are one whitespace-delimited token whose
    // length must equal the stripe count.
    assert!("3 7:0 7:1 7:2 1 AA".parse::<striped::Info>().is_err());
    assert!("2 7:0 7:1 1 AAA".parse::<striped::Info>().is_err());
}

#[test]
fn raid_reports_per_device_health_and_sync_state() {
    let info: raid::Info = round_trip("raid6 6 AAaAAA 131072/2097152 recover 0 0 -");
    assert_eq!(info.raid_type, "raid6");
    assert_eq!(info.devices.len(), 6);
    assert_eq!(info.devices[2], raid::DeviceHealth::OutOfSync);
    assert_eq!(info.devices[0], raid::DeviceHealth::InSync);
    assert_eq!(info.sync_progress, 131_072);
    assert_eq!(info.sync_total, 2_097_152);
    assert_eq!(info.sync_action, raid::SyncAction::Recover);
    assert_eq!(info.mismatches, 0);
    assert_eq!(info.journal, None);

    // A failed device, an idle array, and a journal present.
    let info: raid::Info = round_trip("raid1 2 AD 2097152/2097152 idle 17 2048 A");
    assert_eq!(info.devices[1], raid::DeviceHealth::Dead);
    assert_eq!(info.sync_action, raid::SyncAction::Idle);
    assert_eq!(info.mismatches, 17);
    assert_eq!(info.journal, Some(raid::DeviceHealth::InSync));
}

#[test]
fn raid_rejects_a_health_run_disagreeing_with_the_device_count() {
    assert!(
        "raid1 2 AAA 0/1 idle 0 0 -".parse::<raid::Info>().is_err(),
        "three health chars for two devices"
    );
    assert!(
        "raid1 2 AA 0/1 dancing 0 0 -"
            .parse::<raid::Info>()
            .is_err(),
        "unknown sync action"
    );
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

#[test]
fn thin_reports_mapped_sectors_or_a_failure_keyword() {
    let info: thin::Info = round_trip("32768 65535");
    assert_eq!(
        info,
        thin::Info::Mapped {
            mapped_sectors: 32768,
            highest_mapped_sector: Some(65535),
        }
    );

    let info: thin::Info = round_trip("32768 -");
    assert_eq!(
        info,
        thin::Info::Mapped {
            mapped_sectors: 32768,
            highest_mapped_sector: None,
        }
    );

    assert_eq!(round_trip::<thin::Info>("Fail"), thin::Info::Fail);
    assert_eq!(round_trip::<thin::Info>("Error"), thin::Info::Error);
    // A bare "-" means the volume is not open — distinct from a mapped
    // volume whose highest sector is unknown.
    assert_eq!(round_trip::<thin::Info>("-"), thin::Info::Unopened);
}

#[test]
fn thin_pool_reports_usage_modes_and_flags() {
    // The kernel terminates every field with a space, including the last.
    let line = "7 64/256 4096/16384 - rw discard_passdown queue_if_no_space - 25 ";
    let info: thin_pool::Info = round_trip(line);
    let thin_pool::Info::Active {
        transaction_id,
        used_metadata_blocks,
        total_data_blocks,
        held_metadata_root,
        access_mode,
        discard_mode,
        out_of_space_policy,
        needs_check,
        metadata_low_watermark_blocks,
        ..
    } = info
    else {
        panic!("expected an active pool, got {info:?}");
    };
    assert_eq!(transaction_id, 7);
    assert_eq!(used_metadata_blocks, 64);
    assert_eq!(total_data_blocks, 16384);
    assert_eq!(held_metadata_root, None);
    assert_eq!(access_mode, thin_pool::AccessMode::ReadWrite);
    assert_eq!(discard_mode, thin_pool::DiscardMode::Passdown);
    assert_eq!(out_of_space_policy, thin_pool::OutOfSpacePolicy::Queue);
    assert!(!needs_check);
    assert_eq!(metadata_low_watermark_blocks, 25);
}

#[test]
fn thin_pool_reports_a_pool_that_ran_out_of_data_space() {
    let line = "42 128/256 8192/16384 900 out_of_data_space no_discard_passdown \
                error_if_no_space needs_check 51 ";
    let info: thin_pool::Info = round_trip(line);
    let thin_pool::Info::Active {
        held_metadata_root,
        access_mode,
        needs_check,
        ..
    } = info
    else {
        panic!("expected an active pool");
    };
    assert_eq!(held_metadata_root, Some(900));
    assert_eq!(access_mode, thin_pool::AccessMode::OutOfDataSpace);
    assert!(needs_check);
}

#[test]
fn thin_pool_reports_a_failed_pool_as_a_bare_keyword() {
    assert_eq!(round_trip::<thin_pool::Info>("Fail"), thin_pool::Info::Fail);
    assert!(
        "7 64/256 4096/16384 - sideways discard_passdown queue_if_no_space - 25 "
            .parse::<thin_pool::Info>()
            .is_err()
    );
}

#[test]
fn writecache_reports_fourteen_counters() {
    let line = "0 65536 65000 12 10240 9800 51200 48000 2000 200 100 50 32 16";
    let info: writecache::Info = round_trip(line);
    assert!(!info.has_error);
    assert_eq!(info.blocks, 65536);
    assert_eq!(info.free_blocks, 65000);
    assert_eq!(info.writeback_blocks, 12);
    assert_eq!(info.reads, 10240);
    assert_eq!(info.read_hits, 9800);
    assert_eq!(info.writes, 51200);
    assert_eq!(info.write_hits_uncommitted, 48000);
    assert_eq!(info.write_hits_committed, 2000);
    assert_eq!(info.writes_around, 200);
    assert_eq!(info.writes_allocate, 100);
    assert_eq!(info.writes_blocked_on_freelist, 50);
    assert_eq!(info.flushes, 32);
    assert_eq!(info.discards, 16);

    // A short line must fail rather than leave fields at their defaults.
    assert!("0 65536 65000".parse::<writecache::Info>().is_err());
}

#[test]
fn writecache_reports_a_cache_device_error() {
    let info: writecache::Info = "1 1 1 0 0 0 0 0 0 0 0 0 0 0"
        .parse()
        .expect("parse errored cache");
    assert!(info.has_error);
}

#[test]
fn zoned_reports_keyword_delimited_zone_usage() {
    let line = "4096 zones 0/0 cache 512/512 random 3584/3584 sequential";
    let info: zoned::Info = round_trip(line);
    assert_eq!(info.total_zones, 4096);
    assert_eq!(info.cache.unmapped, 0);
    assert_eq!(info.devices.len(), 1);
    assert_eq!(info.devices[0].random.total, 512);
    assert_eq!(info.devices[0].sequential.unmapped, 3584);
}

#[test]
fn zoned_reports_a_cache_device_with_no_per_device_pair() {
    // With a cache device present the kernel skips the first device's
    // random/sequential pair, so an empty device list is a real shape.
    let info: zoned::Info = round_trip("128 zones 4/16 cache");
    assert_eq!(info.total_zones, 128);
    assert_eq!(info.cache.total, 16);
    assert_eq!(info.devices, []);
}

#[test]
fn zoned_rejects_a_line_with_the_wrong_keywords() {
    assert!("4096 blocks 0/0 cache".parse::<zoned::Info>().is_err());
    assert!(
        "4096 zones 0/0 cache 512/512 sequential 1/1 random"
            .parse::<zoned::Info>()
            .is_err()
    );
}
