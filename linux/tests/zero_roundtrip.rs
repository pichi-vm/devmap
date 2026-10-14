// SPDX-License-Identifier: Apache-2.0

//! End-to-end validation of the whole generic plumbing (`Control`,
//! `Table`, `Rows`, the ioctl sequence itself) via the simplest
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

use std::{fs::File, io::Read as _};

use devmap_core::Span;
use devmap_linux::records::Records;
use devmap_linux::targets::Zero;
use devmap_linux::{DevId, Status};

use common::{Owned, open_control};

#[test]
fn create_load_resume_read_zeros_remove() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-zero-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let mut file = File::open(dev.node_path())
        .unwrap_or_else(|e| panic!("open {} ({}): {e}", dev.node_path().display(), dev.id()));

    let mut buf = [0xFFu8; 4096];
    file.read_exact(&mut buf).expect("read from dm-zero device");
    assert!(
        buf.iter().all(|&b| b == 0),
        "dm-zero must read back as all zeros"
    );

    // dm-zero has no `.status` callback, so its info row parses as ().
    let mut status = control
        .info::<4096>(dev.id())
        .expect("DM_TABLE_STATUS (info)");
    let info = status.next().unwrap().unwrap();
    info.parse::<Zero>(control.version("zero").unwrap())
        .unwrap();

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

    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let status = control.status(dev.id()).expect("DM_DEV_STATUS");
    assert!(
        status.flags & Status::SUSPENDED == 0,
        "device should not be suspended after resume()"
    );

    control
        .suspend(dev.id(), true)
        .expect("DM_DEV_SUSPEND (suspend)");
    let status = control.status(dev.id()).expect("DM_DEV_STATUS");
    assert!(
        status.flags & Status::SUSPENDED != 0,
        "device should be suspended after suspend()"
    );

    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume again)");
    let status = control.status(dev.id()).expect("DM_DEV_STATUS");
    assert!(
        status.flags & Status::SUSPENDED == 0,
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

    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let status = control.status(dev.id()).expect("DM_DEV_STATUS");
    assert_eq!(status.target_count, 1);
    assert!(status.open_count >= 0);
}

#[test]
fn table_status_reports_back_the_loaded_target() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-tstatus-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let mut table = control.table::<4096>(dev.id()).expect("DM_TABLE_STATUS");
    let reported = table.next().unwrap().unwrap();
    let row = &reported;
    assert_eq!(row.span(), Span::new(0, 8192));
    assert_eq!(
        row.parse::<Zero>(control.version("zero").unwrap()).unwrap(),
        Zero
    );
}

#[test]
fn list_reports_the_created_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-list-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let mut reply = control.devices::<4096>().expect("DM_LIST_DEVICES");
    let mut found = None;
    while let Some(record) = reply.next() {
        let (listed_name, id) = record.expect("decode device");
        if listed_name == name {
            found = Some(id);
            break;
        }
    }
    assert_eq!(
        found,
        Some(dev.id()),
        "device {name} not found in DM_LIST_DEVICES output"
    );
}

#[test]
fn fixed_capacity_queries_report_full_buffers_and_allow_larger_retries() {
    let Some(control) = open_control() else {
        return;
    };
    let name = format!("devmap-test-capacity-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    control
        .load(
            dev.id(),
            devmap_linux::Table::<48>::default()
                .add(
                    devmap_core::Span::new(0, 8),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("exact-fit row"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control.suspend(dev.id(), false).expect("resume");

    assert_eq!(
        control.table::<0>(dev.id()).unwrap_err().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert_eq!(
        control.info::<47>(dev.id()).unwrap_err().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert_eq!(
        control.deps::<0>(dev.id()).unwrap_err().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert!(
        matches!(control.devices::<0>(), Err(error) if error.kind() == std::io::ErrorKind::StorageFull)
    );
    assert!(
        matches!(control.versions::<0>(), Err(error) if error.kind() == std::io::ErrorKind::StorageFull)
    );

    let mut table = control.table::<48>(dev.id()).expect("exact-fit response");
    let rows = table.next().unwrap().unwrap();
    assert_eq!(
        rows.parse::<Zero>(control.version("zero").unwrap())
            .unwrap(),
        Zero
    );
    let mut info = control.info::<49>(dev.id()).unwrap();
    assert!(info.next().unwrap().is_ok());
    assert!(info.next().is_none());
    assert!(control.deps::<8>(dev.id()).unwrap().next().is_none());
}

#[test]
fn by_device_and_by_node_attach_to_an_existing_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-attach-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let id = dev.id();
    let (major, minor) = (id.major(), id.minor());

    let by_device = DevId::new(major, minor).expect("in range");
    assert_eq!(
        control
            .status(by_device)
            .expect("DM_DEV_STATUS via by_device")
            .target_count,
        1
    );

    let by_node = DevId::try_from(std::fs::metadata(dev.node_path()).unwrap()).unwrap();
    assert_eq!(by_node, id);
}

#[test]
fn by_name_finds_device_and_reports_status() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-byname-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    let (device, status) = control.by_name(&name).expect("DM_DEV_STATUS by_name");
    assert_eq!(device, dev.id());
    assert_eq!(status.target_count, 1);
}

#[test]
fn dropping_a_connection_leaves_the_device_alone() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-drop-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    let connection = control.clone();
    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    drop(control);
    let control = connection;
    let (survivor, _) = control
        .by_name(&name)
        .expect("dropping a handle must not remove the device");

    // Removal is explicit, and it reports its own success.
    assert_eq!(survivor, dev.id());
    dev.remove(false).expect("DM_DEV_REMOVE");
    assert!(
        control.by_name(&name).is_err(),
        "the device is gone once it is actually removed"
    );
}

#[test]
fn deferred_removal_reclaims_a_device_that_is_still_open() {
    // Open a holder before requesting kernel-managed deferred removal.
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-deferred-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    control
        .load(
            dev.id(),
            devmap_linux::Table::<4096>::default()
                .add(
                    devmap_core::Span::new(0, 8192),
                    &Zero,
                    control.version("zero").unwrap(),
                )
                .expect("add zero"),
            false,
        )
        .expect("DM_TABLE_LOAD");
    control
        .suspend(dev.id(), false)
        .expect("DM_DEV_SUSPEND (resume)");

    // Held open, an immediate removal would be refused rather than silently
    // deferred. No deferred removal has been requested yet.
    let file = File::open(dev.node_path()).expect("open active device");
    let err = control
        .remove(dev.id(), false)
        .expect_err("an open device cannot be removed immediately");
    assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy);
    let holder = file;
    dev.remove(true).expect("defer removal");

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
