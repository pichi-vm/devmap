// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `writecache` and `integrity`.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap::targets::integrity::Mode;
use devmap::targets::writecache::Kind;
use devmap::targets::{Integrity, Writecache};

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
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            16 * 1024 * 1024 / 512,
            Writecache::builder(Kind::Ssd, origin_device.id(), cache_device.id(), 4096).build(),
        )
        .expect("add writecache")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{minor}"))
        .expect("open");
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

    let name = format!("devmap-test-integrity-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    let target = || {
        Integrity::builder(backing_device.id(), 0, Mode::Journaled)
            .internal_hash("sha256")
            .build()
    };

    // First load: 1-sector table lets the kernel format the (all-zero)
    // superblock rather than rejecting a mismatched size outright.
    removed
        .builder()
        .add(0, 1, target())
        .expect("add integrity")
        .load()
        .expect("DM_TABLE_LOAD (format)");
    removed.resume().expect("resume (format)");
    removed.suspend().expect("suspend before reload");

    // Reload with a conservative size well under the raw device's sector
    // count — dm-integrity reserves journal/tag space internally, so the
    // real `provided_data_sectors` is always smaller than the raw device;
    // a real caller reads that exact value back from the superblock, but
    // for this test any value safely inside it is enough to prove the
    // reload sequence itself works.
    let real_length = 8 * 1024 * 1024 / 512;
    removed
        .builder()
        .add(0, real_length, target())
        .expect("add integrity")
        .load()
        .expect("DM_TABLE_LOAD (real size)");
    removed.resume().expect("resume (real size)");

    let status = removed.status().expect("DM_DEV_STATUS");
    assert_eq!(status.target_count(), 1);

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
    let rows: Vec<_> = removed.table().expect("DM_TABLE_STATUS").collect();
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
