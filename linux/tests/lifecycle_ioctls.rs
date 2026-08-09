// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for the device lifecycle ioctls beyond
//! create/load/resume/remove: `DM_TABLE_DEPS`, `DM_TABLE_CLEAR`,
//! `DM_DEV_WAIT`, `DM_DEV_RENAME`, and `DM_LIST_VERSIONS`.
//!
//! `DM_DEV_ARM_POLL` is covered in `arm_poll.rs` instead — it watches a
//! subsystem-wide counter, so it cannot share a test binary with tests
//! that create devices concurrently.

mod common;

use common::{LoopDevice, open_control};
use devmap_linux::targets::{Linear, Zero};

#[test]
fn deps_reports_the_devices_the_table_opens() {
    let Some(control) = open_control() else {
        return;
    };

    let backing = LoopDevice::create("deps", 8 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing");

    let name = format!("devmap-test-deps-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            8 * 1024 * 1024 / 512,
            Linear {
                device: backing_device.id(),
                offset_sectors: 0,
            },
        )
        .expect("add linear")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // A linear mapping opens exactly the one device it maps.
    let deps = removed.deps().expect("DM_TABLE_DEPS");
    assert_eq!(
        deps,
        [backing_device.id()],
        "deps must name the loop device"
    );
}

#[test]
fn deps_is_empty_for_a_target_that_opens_no_devices() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-deps-zero-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // dm-zero is purely synthetic — it opens nothing.
    assert_eq!(removed.deps().expect("DM_TABLE_DEPS"), []);
}

#[test]
fn clear_inactive_table_discards_the_staged_table() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-clear-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");

    // Stage and activate a first table so the device has an active one.
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");
    assert!(
        removed.status().expect("status").has_active_table(),
        "the resumed table is active"
    );

    // Stage a second, larger table but do NOT resume it.
    removed
        .builder()
        .add(0, 16384, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD (staged)");
    assert!(
        removed.status().expect("status").has_inactive_table(),
        "the staged table is inactive"
    );

    removed
        .clear_inactive_table()
        .expect("DM_TABLE_CLEAR must discard the staged table");

    let status = removed.status().expect("status");
    assert!(
        !status.has_inactive_table(),
        "the staged table must be gone after a clear"
    );
    assert!(
        status.has_active_table(),
        "clearing the inactive table must leave the active one alone"
    );
}

#[test]
fn clear_inactive_table_is_a_no_op_with_nothing_staged() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-clear-noop-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // Nothing is staged; clearing must succeed rather than error.
    removed
        .clear_inactive_table()
        .expect("clearing with nothing staged is not an error");
    assert!(!removed.status().expect("status").has_inactive_table());
}

#[test]
fn rename_moves_the_device_to_the_new_name() {
    let Some(control) = open_control() else {
        return;
    };

    let old = format!("devmap-test-rename-old-{}", std::process::id());
    let new = format!("devmap-test-rename-new-{}", std::process::id());
    let removed = control.create(&old).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");
    let id = removed.id();

    let renamed = control.rename(&old, &new).expect("DM_DEV_RENAME");
    assert_eq!(renamed.id(), id, "rename keeps the same dev_t");

    // The new name resolves and the old one is gone.
    let (found, _) = control.by_name(&new).expect("by_name after rename");
    assert_eq!(found.id(), id);
    assert!(
        control.by_name(&old).is_err(),
        "the old name must no longer resolve"
    );
}

#[test]
fn rename_rejects_a_name_already_in_use() {
    let Some(control) = open_control() else {
        return;
    };

    let first = format!("devmap-test-rename-clash-a-{}", std::process::id());
    let second = format!("devmap-test-rename-clash-b-{}", std::process::id());
    let a = control.create(&first).expect("create first");
    a.builder()
        .add(0, 8192, Zero)
        .expect("add")
        .load()
        .expect("load");
    a.resume().expect("resume");
    let b = control.create(&second).expect("create second");
    b.builder()
        .add(0, 8192, Zero)
        .expect("add")
        .load()
        .expect("load");
    b.resume().expect("resume");

    assert!(
        control.rename(&first, &second).is_err(),
        "renaming onto a live name must fail rather than clobber it"
    );
}

#[test]
fn set_uuid_attaches_a_uuid_that_by_uuid_then_finds() {
    let Some(control) = open_control() else {
        return;
    };

    // `create` never assigns a uuid, so DM_DEV_RENAME with DM_UUID_FLAG is
    // the only way to give a device one — and the only way `by_uuid` can
    // be exercised against a real device at all.
    let name = format!("devmap-test-uuid-{}", std::process::id());
    let uuid = format!("devmap-test-uuid-value-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");
    let id = removed.id();

    control
        .set_uuid(&name, &uuid)
        .expect("DM_DEV_RENAME (uuid)");

    let (found, _) = control.by_uuid(&uuid).expect("by_uuid after set_uuid");
    assert_eq!(found.id(), id);

    // The kernel allows a uuid to be set once, never changed.
    let other = format!("{uuid}-again");
    assert!(
        control.set_uuid(&name, &other).is_err(),
        "a device's uuid must not be replaceable once set"
    );
}

#[test]
fn list_versions_reports_the_targets_the_kernel_has_registered() {
    let Some(control) = open_control() else {
        return;
    };

    let versions = control.list_versions().expect("DM_LIST_VERSIONS");
    assert!(
        !versions.is_empty(),
        "a kernel with device-mapper has at least one target registered"
    );
    // dm-zero and dm-linear are built into any dm-capable kernel that can
    // run the rest of this suite.
    for expected in ["zero", "linear"] {
        let found = versions.iter().find(|t| t.name == expected);
        let target = found.unwrap_or_else(|| panic!("{expected} must be registered: {versions:?}"));
        assert!(
            target.version[0] >= 1,
            "{expected} version looks unset: {:?}",
            target.version
        );
    }
}

#[test]
fn wait_event_returns_at_once_when_the_counter_already_differs() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-wait-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // The kernel blocks only while the passed value EQUALS the device's
    // current counter, so a value that differs returns immediately. This
    // is the same path a caller hits when an event fired between reading
    // the status and waiting on it, and it keeps the test from hanging.
    let event_nr = removed.status().expect("status").event_nr();
    let status = removed
        .wait_event(event_nr.wrapping_add(1))
        .expect("DM_DEV_WAIT");
    assert_eq!(
        status.event_nr(),
        event_nr,
        "wait returns the device's real counter, not the value waited on"
    );
    assert!(status.has_active_table());
}
