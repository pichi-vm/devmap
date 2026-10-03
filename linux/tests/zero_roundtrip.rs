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

use std::{
    fs::{File, OpenOptions},
    io::Read as _,
};

use common::{Owned, open_control};
use devmap_linux::target::zero::ZeroTarget;
use devmap_linux::{Defer as _, DevId, device::Status, target::Empty};

#[test]
fn create_load_resume_read_zeros_remove() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-zero-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");

    dev.builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let mut file = File::open(dev.node_path())
        .unwrap_or_else(|e| panic!("open {} ({}): {e}", dev.node_path().display(), dev.id()));

    let mut buf = [0xFFu8; 4096];
    file.read_exact(&mut buf).expect("read from dm-zero device");
    assert!(
        buf.iter().all(|&b| b == 0),
        "dm-zero must read back as all zeros"
    );

    // dm-zero has no `.status` callback, so its info row parses as Empty.
    let info: Vec<_> = dev.info().expect("DM_TABLE_STATUS (info)").collect();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].parse::<ZeroTarget>().unwrap(), Empty);

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
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = dev.status().expect("DM_DEV_STATUS");
    assert!(
        status.flags & Status::SUSPENDED == 0,
        "device should not be suspended after resume()"
    );

    dev.suspend().expect("DM_DEV_SUSPEND (suspend)");
    let status = dev.status().expect("DM_DEV_STATUS");
    assert!(
        status.flags & Status::SUSPENDED != 0,
        "device should be suspended after suspend()"
    );

    dev.resume().expect("DM_DEV_SUSPEND (resume again)");
    let status = dev.status().expect("DM_DEV_STATUS");
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

    dev.builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let status = dev.status().expect("DM_DEV_STATUS");
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

    dev.builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let reported: Vec<_> = dev.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(reported.len(), 1);
    let row = &reported[0];
    assert_eq!(row.start(), 0);
    assert_eq!(row.length(), 8192);
    assert_eq!(row.parse::<ZeroTarget>().unwrap(), ZeroTarget);
}

#[test]
fn list_reports_the_created_device() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-list-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let found = control
        .devices()
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
        .add(0, 8192, ZeroTarget)
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
            .target_count,
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
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    let (device, status) = control.by_name(&name).expect("DM_DEV_STATUS by_name");
    assert_eq!(device.id(), dev.id());
    assert_eq!(status.target_count, 1);
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
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    drop(dev);
    let (survivor, _) = control
        .by_name(&name)
        .expect("dropping a handle must not remove the device");

    // Removal is explicit, and it reports its own success.
    survivor.remove(false).expect("DM_DEV_REMOVE");
    assert!(
        control.by_name(&name).is_err(),
        "the device is gone once it is actually removed"
    );
}

#[test]
fn guard_drop_removes_but_disarm_preserves() {
    let Some(control) = open_control() else {
        return;
    };

    let dropped = format!("devmap-test-guard-drop-{}", std::process::id());
    drop(control.create(&dropped).expect("DM_DEV_CREATE").guard());
    assert!(control.by_name(&dropped).is_err());

    let disarmed = format!("devmap-test-guard-disarm-{}", std::process::id());
    let device = control
        .create(&disarmed)
        .expect("DM_DEV_CREATE")
        .guard()
        .disarm();
    control
        .by_name(&disarmed)
        .expect("disarmed device remains persistent");
    device.remove(false).expect("DM_DEV_REMOVE");
}

#[test]
fn guard_defer_rolls_back_when_opening_fails() {
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-guard-rollback-{}", std::process::id());
    let guard = control.create(&name).expect("DM_DEV_CREATE").guard();
    guard
        .builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    guard.resume().expect("DM_DEV_SUSPEND (resume)");

    let error = guard
        .defer(&OpenOptions::new())
        .expect_err("options without access mode must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        control.by_name(&name).is_err(),
        "failed defer must roll back the mapping"
    );
}

#[test]
fn deferred_removal_reclaims_a_device_that_is_still_open() {
    // `Guard::defer` opens the device before requesting deferred removal, so
    // the returned file owns the remainder of the mapping's lifetime.
    let Some(control) = open_control() else {
        return;
    };

    let name = format!("devmap-test-deferred-{}", std::process::id());
    let dev = control.create(&name).expect("DM_DEV_CREATE").guard();
    dev.builder()
        .add(0, 8192, ZeroTarget)
        .expect("add zero")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("DM_DEV_SUSPEND (resume)");

    // Held open, an immediate removal would be refused rather than silently
    // deferred. The guard has not changed kernel removal policy yet.
    let file = File::open(dev.node_path()).expect("open active device");
    let err = dev
        .clone()
        .remove(false)
        .expect_err("an open device cannot be removed immediately");
    assert_eq!(err.kind(), std::io::ErrorKind::ResourceBusy);
    drop(file);

    let mut options = OpenOptions::new();
    options.read(true);
    let holder = match dev.defer(&options) {
        Ok(file) => file,
        Err(e) => {
            panic!("defer active device: {e}");
        }
    };

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

#[cfg(feature = "tokio")]
mod async_defer {
    use devmap_linux::AsyncDefer as _;
    use tokio::io::AsyncReadExt as _;

    use super::{ZeroTarget, open_control};

    #[tokio::test]
    async fn deferred_removal_returns_a_tokio_holder() {
        let Some(control) = open_control() else {
            return;
        };

        let name = format!("devmap-test-async-deferred-{}", std::process::id());
        let dev = control.create(&name).expect("DM_DEV_CREATE").guard();
        dev.builder()
            .add(0, 8192, ZeroTarget)
            .expect("add zero")
            .load()
            .expect("DM_TABLE_LOAD");
        dev.resume().expect("DM_DEV_SUSPEND (resume)");

        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        let mut holder = dev
            .defer(&options)
            .await
            .expect("asynchronously defer active device");

        let mut sector = [1_u8; 512];
        holder
            .read_exact(&mut sector)
            .await
            .expect("read from dm-zero device");
        assert_eq!(sector, [0; 512]);
        control
            .by_name(&name)
            .expect("mapping remains while the Tokio holder is open");

        drop(holder);
        let gone = tokio::task::spawn_blocking(move || {
            (0..50).any(|_| {
                if control.by_name(&name).is_err() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                false
            })
        })
        .await
        .expect("join removal poll");
        assert!(gone, "the kernel must reclaim the device once it is closed");
    }

    #[tokio::test]
    async fn failed_async_open_rolls_back_the_mapping() {
        let Some(control) = open_control() else {
            return;
        };

        let name = format!("devmap-test-async-rollback-{}", std::process::id());
        let guard = control.create(&name).expect("DM_DEV_CREATE").guard();
        guard
            .builder()
            .add(0, 8192, ZeroTarget)
            .expect("add zero")
            .load()
            .expect("DM_TABLE_LOAD");
        guard.resume().expect("DM_DEV_SUSPEND (resume)");

        let error = guard
            .defer(&tokio::fs::OpenOptions::new())
            .await
            .expect_err("options without an access mode must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            control.by_name(&name).is_err(),
            "failed async defer must roll back the mapping"
        );
    }

    #[tokio::test]
    async fn cancelling_async_defer_still_reclaims_the_mapping() {
        let Some(control) = open_control() else {
            return;
        };

        let name = format!("devmap-test-async-cancel-{}", std::process::id());
        let guard = control.create(&name).expect("DM_DEV_CREATE").guard();
        guard
            .builder()
            .add(0, 8192, ZeroTarget)
            .expect("add zero")
            .load()
            .expect("DM_TABLE_LOAD");
        guard.resume().expect("DM_DEV_SUSPEND (resume)");

        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        let operation = tokio::spawn(async move { guard.defer(&options).await });
        tokio::task::yield_now().await;
        operation.abort();
        let _ = operation.await;

        let gone = tokio::task::spawn_blocking(move || {
            (0..50).any(|_| {
                if control.by_name(&name).is_err() {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                false
            })
        })
        .await
        .expect("join removal poll");
        assert!(gone, "cancelled async defer must not leak the mapping");
    }
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
