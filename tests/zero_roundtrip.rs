// SPDX-License-Identifier: Apache-2.0

//! End-to-end validation of the whole generic plumbing (`Control`,
//! `Device`, `DmTableBuf`, the ioctl sequence itself) via the simplest
//! possible target: dm-zero has no parameters, so this exercises
//! everything *except* target-specific parameter rendering.
//!
//! Requires root (or `CAP_SYS_ADMIN`) to open `/dev/mapper/control` for
//! writing — skips gracefully otherwise, matching the pattern this
//! project's other ioctl-touching tests already use.
//!
//! `by_uuid()` is deliberately not exercised here: `Control::create`
//! never assigns a uuid, and `DM_DEV_RENAME` (the only ioctl that could
//! attach one after the fact) isn't implemented by this crate, so there
//! is no way to get a real device into a state where `by_uuid` would
//! find it.

use std::io::Read as _;

use devmap::{Control, targets::Zero};

/// Returns `None` (and prints a skip notice) if this process can't open
/// `/dev/mapper/control` — i.e. isn't root / doesn't have `CAP_SYS_ADMIN`.
fn open_control() -> Option<Control> {
    if let Ok(control) = Control::open() {
        return Some(control);
    }
    eprintln!("skip: requires root (or CAP_SYS_ADMIN) for /dev/mapper/control");
    None
}

#[test]
fn create_load_resume_read_zeros_remove() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-zero-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let id = removed.id();
    let (major, minor) = (id.major(), id.minor());
    let path = format!("/dev/dm-{minor}");
    let mut file = std::fs::File::open(&path)
        .unwrap_or_else(|e| panic!("open {path} (major={major}, minor={minor}): {e}"));

    let mut buf = [0xFFu8; 4096];
    file.read_exact(&mut buf).expect("read from dm-zero device");
    assert!(
        buf.iter().all(|&b| b == 0),
        "dm-zero must read back as all zeros"
    );

    // `removed` drops here: best-effort DM_DEV_REMOVE.
}

#[test]
fn suspend_resume_round_trips() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-suspend-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = removed.status().expect("DM_DEV_STATUS");
    assert!(
        !status.is_suspended(),
        "device should not be suspended after resume()"
    );

    removed.suspend().expect("DM_DEV_SUSPEND (suspend)");
    let status = removed.status().expect("DM_DEV_STATUS");
    assert!(
        status.is_suspended(),
        "device should be suspended after suspend()"
    );

    removed.resume().expect("DM_DEV_SUSPEND (resume again)");
    let status = removed.status().expect("DM_DEV_STATUS");
    assert!(
        !status.is_suspended(),
        "device should not be suspended after resuming again"
    );
}

#[test]
fn status_reports_sane_values_for_a_fresh_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-status-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = removed.status().expect("DM_DEV_STATUS");
    assert_eq!(status.target_count(), 1);
    assert!(status.open_count() >= 0);
}

#[test]
fn table_status_reports_back_the_loaded_target() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-tstatus-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let reported: Vec<_> = removed.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(reported.len(), 1);
    let row = &reported[0];
    assert_eq!(row.start(), 0);
    assert_eq!(row.length(), 8192);
    assert_eq!(row.type_name(), "zero");
    assert_eq!(row.parse::<Zero>(), Some(Zero));
}

#[test]
fn list_reports_the_created_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-list-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let found = control
        .list()
        .expect("DM_LIST_DEVICES")
        .find(|(listed_name, _)| *listed_name == name)
        .unwrap_or_else(|| panic!("device {name} not found in DM_LIST_DEVICES output"));
    assert_eq!(found.1.id(), removed.id());
}

#[test]
fn by_device_and_by_node_attach_to_an_existing_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-attach-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let id = removed.id();
    let (major, minor) = (id.major(), id.minor());

    let by_device = control.by_device((major, minor));
    assert_eq!(
        by_device
            .status()
            .expect("DM_DEV_STATUS via by_device")
            .target_count(),
        1
    );

    let path = format!("/dev/dm-{minor}");
    let by_node = control.by_node(&path).expect("by_node");
    assert_eq!(by_node.id(), id);
}

#[test]
fn by_name_finds_device_and_reports_status() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-byname-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("DM_DEV_SUSPEND (resume)");

    let (device, status) = control.by_name(&name).expect("DM_DEV_STATUS by_name");
    assert_eq!(device.id(), removed.id());
    assert_eq!(status.target_count(), 1);
}

#[test]
fn create_rejects_a_duplicate_name() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-dup-{}", std::process::id());
    let _removed = control.create(&name).expect("DM_DEV_CREATE");

    let err = control
        .create(&name)
        .expect_err("creating the same name twice must fail");
    assert!(
        matches!(err, devmap::Error::NameConflict { .. }),
        "expected NameConflict, got {err:?}"
    );
}
