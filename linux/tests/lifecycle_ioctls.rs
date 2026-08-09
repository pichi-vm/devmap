// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for the device lifecycle ioctls beyond
//! create/load/resume/remove: `DM_TABLE_DEPS`, `DM_TABLE_CLEAR`, and
//! `DM_DEV_WAIT`.

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
