// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `writecache` and `integrity`.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};

use common::{LoopDevice, Owned, ensure_module_loaded, open_control};
use devmap_linux::targets::integrity::Mode;
use devmap_linux::targets::writecache::Kind;
use devmap_linux::targets::{Integrity, Writecache};

#[test]
fn writecache_passes_data_through() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-writecache");

    let origin = LoopDevice::create("writecache-origin", 16 * 1024 * 1024);
    let cache = LoopDevice::create("writecache-cache", 8 * 1024 * 1024);
    let origin_device = control.by_node(&origin.path).expect("by_node origin");
    let cache_device = control.by_node(&cache.path).expect("by_node cache");

    let name = format!("devmap-test-writecache-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(
            0,
            16 * 1024 * 1024 / 512,
            Writecache::builder(Kind::Ssd, origin_device.id(), cache_device.id(), 4096).build(),
        )
        .expect("add writecache")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("resume");

    let mut file = dev.open_rw().expect("open");
    let pattern = [0x5Au8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);
}

/// Exercises `dm-integrity`'s documented first-use sequence: zero the
/// superblock (a fresh loop device already reads as zero), load a
/// 1-sector table so the kernel formats the device and reports the real
/// `provided_data_sectors` back via status, then reload with that size.
/// This state machine is the *caller's* responsibility per
/// `Integrity`'s doc comment — devmap only needs to render each
/// table line correctly, which this test verifies against a real kernel.
#[test]
fn integrity_first_use_format_then_reload_sequence() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-integrity");

    let backing = LoopDevice::create("integrity", 32 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing");

    let target = Integrity::builder(backing_device.id(), 0, Mode::Journaled)
        .internal_hash("sha256")
        .build();

    // Format for first use and get the usable capacity back — the whole
    // two-step dance, done with no external tool.
    let format_name = format!("devmap-test-integrity-fmt-{}", std::process::id());
    let provided_data_sectors = target
        .format(&control, &format_name, &backing.path)
        .expect("Integrity::format");
    assert!(
        provided_data_sectors > 0,
        "the formatted device must report a usable capacity"
    );
    // The reserved journal and tag space means usable is strictly less
    // than the raw device.
    assert!(
        provided_data_sectors < 32 * 1024 * 1024 / 512,
        "usable capacity must be under the raw device size"
    );

    // Load the real table at the capacity the format reported.
    let name = format!("devmap-test-integrity-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, provided_data_sectors, target.clone())
        .expect("add integrity")
        .load()
        .expect("DM_TABLE_LOAD (real size)");
    dev.resume().expect("resume (real size)");

    let status = dev.status().expect("DM_DEV_STATUS");
    assert_eq!(status.target_count(), 1);

    let real_length = provided_data_sectors;

    // dm-integrity reports the full effective configuration, not the four
    // arguments devmap wrote. `Integrity` renders
    //
    //     7:0 0 - J 1 internal_hash:sha256
    //
    // and the kernel answers with a concrete tag size in place of `-` and
    // the journal/buffer geometry it chose for itself:
    //
    //     7:0 0 32 J 6 interleave_sectors:32768 buffer_sectors:128 \
    //     journal_sectors:440 journal_watermark:50 commit_time:10000 \
    //     internal_hash:sha256
    //
    // Those values depend on the device size, so assert that each field is
    // present rather than on the numbers. This asymmetry is why the table
    // read shape is a type of its own rather than `Integrity` itself.
    let rows: Vec<_> = dev.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].type_name(), "integrity");

    let table = rows[0]
        .parse::<Integrity>()
        .expect("read the row as integrity's table type");
    assert_eq!(table.device, backing_device.id());
    assert_eq!(table.mode, Mode::Journaled);
    assert_eq!(table.internal_hash.as_deref(), Some("sha256"));
    // The kernel answers the `-` devmap wrote with a concrete tag size,
    // and fills in the journal geometry it chose for itself.
    assert!(table.tag_size > 0);
    assert!(table.buffer_sectors > 0);
    assert!(table.journal_sectors.is_some());
    assert!(table.journal_watermark_percent.is_some());
    assert!(table.commit_time_ms.is_some());

    // Reading is faithful: the parsed value renders back to the exact line
    // the kernel gave.
    assert_eq!(
        rows[0].to_string(),
        format!("0 {real_length} integrity {table}")
    );
}
