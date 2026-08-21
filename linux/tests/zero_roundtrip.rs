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
//! `by_uuid()` is not exercised here because `Control::create` never
//! assigns a uuid; `lifecycle_ioctls.rs` covers it, attaching one first
//! with `Control::set_uuid`.

mod common;

use std::io::Read as _;

use common::{Owned, open_control};
use devmap_linux::{DevId, targets::Zero};

#[test]
fn create_load_resume_read_zeros_remove() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-zero-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let mut file = dev
        .open()
        .unwrap_or_else(|e| panic!("open {} ({}): {e}", dev.node_path().display(), dev.id()));

    let mut buf = [0xFFu8; 4096];
    file.read_exact(&mut buf).expect("read from dm-zero device");
    assert!(
        buf.iter().all(|&b| b == 0),
        "dm-zero must read back as all zeros"
    );

    // dm-zero has no `.status` callback at all, so the kernel emits an
    // empty params field for it — which is exactly what `NoInfo` accepts
    // and nothing else.
    let info: Vec<_> = dev.info().expect("DM_TABLE_STATUS (info)").collect();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].params(), "");
    assert_eq!(info[0].parse::<Zero>(), Some(devmap_linux::NoInfo));

    // The test harness's `Owned` guard drops here and removes the mapping;
    // the library itself never removes anything implicitly.
}

#[test]
fn suspend_resume_round_trips() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-suspend-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = dev.status().expect("DM_DEV_STATUS");
    assert!(
        !status.is_suspended(),
        "device should not be suspended after resume()"
    );

    dev.suspend().expect("DM_DEV_SUSPEND (suspend)");
    let status = dev.status().expect("DM_DEV_STATUS");
    assert!(
        status.is_suspended(),
        "device should be suspended after suspend()"
    );

    dev.resume().expect("DM_DEV_SUSPEND (resume again)");
    let status = dev.status().expect("DM_DEV_STATUS");
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
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = dev.status().expect("DM_DEV_STATUS");
    assert_eq!(status.target_count(), 1);
    assert!(status.open_count() >= 0);
}

#[test]
fn table_status_reports_back_the_loaded_target() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-tstatus-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let reported: Vec<_> = dev.table().expect("DM_TABLE_STATUS").collect();
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
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let found = control
        .list()
        .expect("DM_LIST_DEVICES")
        .find(|(listed_name, _)| *listed_name == name)
        .unwrap_or_else(|| panic!("device {name} not found in DM_LIST_DEVICES output"));
    assert_eq!(found.1.id(), dev.id());
}

#[test]
fn by_device_and_by_node_attach_to_an_existing_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-attach-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let id = dev.id();
    let (major, minor) = (id.major(), id.minor());

    let by_device = control.by_device(DevId::new(major, minor).expect("in range"));
    assert_eq!(
        by_device
            .status()
            .expect("DM_DEV_STATUS via by_device")
            .target_count(),
        1
    );

    let by_node = control.by_node(dev.node_path()).expect("by_node");
    assert_eq!(by_node.id(), id);
}

#[test]
fn by_name_finds_device_and_reports_status() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-byname-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let (device, status) = control.by_name(&name).expect("DM_DEV_STATUS by_name");
    assert_eq!(device.id(), dev.id());
    assert_eq!(status.target_count(), 1);
}

#[test]
fn dropping_a_handle_leaves_the_device_alone() {
    // The core of the no-autoremoval contract: a `Device` is a handle to
    // kernel state, and letting it go must not touch that state. Anything
    // else would mean an error path or a panic could tear down a device the
    // caller still wants — and would silently do so, since `Drop` has
    // nowhere to report a failure.
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-drop-{}", std::process::id());
    let dev = control.create(&name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    drop(dev);
    let (survivor, _) = control
        .by_name(&name)
        .expect("dropping a handle must not remove the device");

    // Removal is explicit, and it reports its own success.
    survivor.remove().expect("DM_DEV_REMOVE");
    assert!(
        control.by_name(&name).is_err(),
        "the device is gone once it is actually removed"
    );
}

#[test]
fn deferred_removal_reclaims_a_device_that_is_still_open() {
    // The kernel's autoremoval, and the reason a Drop guard isn't needed:
    // `remove_deferred` succeeds against an open device and the kernel
    // tears it down when the last holder closes it. An immediate `remove`
    // in the same position returns EBUSY.
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-deferred-{}", std::process::id());
    let dev = control.create(&name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, Zero)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let holder = match dev.open() {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "skip: {} not available yet ({e})",
                dev.node_path().display()
            );
            dev.remove_deferred().ok();
            return;
        }
    };

    // Held open, so an immediate removal must be refused rather than
    // silently deferred.
    let err = dev
        .clone()
        .remove()
        .expect_err("an open device cannot be removed immediately");
    assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy);

    // Deferred removal is accepted, and the device survives until the
    // holder lets go.
    dev.remove_deferred().expect("DM_DEV_REMOVE (deferred)");
    control
        .by_name(&name)
        .expect("still present while a holder has it open");

    drop(holder);
    let gone = (0..50).any(|_| {
        if control.by_name(&name).is_err() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        false
    });
    assert!(gone, "the kernel must reclaim the device once it is closed");
}

#[test]
fn create_rejects_a_duplicate_name() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-dup-{}", std::process::id());
    let _dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    let err = control
        .create(&name)
        .expect_err("creating the same name twice must fail");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::ResourceBusy
        ),
        "expected AlreadyExists/ResourceBusy, got {err:?}"
    );
}
