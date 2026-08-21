// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `dm-raid`: a minimal `raid1` (mirror) over
//! two loop devices, with no dedicated metadata devices.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use common::{LoopDevice, Owned, ensure_module_loaded, open_control};
use devmap_linux::targets::Raid;
use devmap_linux::targets::raid::{DeviceHealth, DevicePair, Type};

#[test]
fn raid1_mirrors_writes_across_two_devices() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-raid");

    let disk0 = LoopDevice::create("raid1-disk0", 16 * 1024 * 1024);
    let disk1 = LoopDevice::create("raid1-disk1", 16 * 1024 * 1024);
    let disk0_device = control.by_node(&disk0.path).expect("by_node disk0");
    let disk1_device = control.by_node(&disk1.path).expect("by_node disk1");

    let name = format!("devmap-test-raid1-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    let length = 16 * 1024 * 1024 / 512;
    let target = Raid::new(
        Type::Raid1,
        128,
        vec![
            DevicePair::data_only(disk0_device.id()),
            DevicePair::data_only(disk1_device.id()),
        ],
    );
    let written = target.to_string();
    dev.builder()
        .add(0, length, target)
        .expect("add raid")
        .load()
        .expect("DM_TABLE_LOAD");
    dev.resume().expect("resume");

    // Wait for the initial sync to at least start reporting via status
    // (raid1 is usable immediately, but give the personality a moment to
    // initialize before exercising it).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = dev.status().expect("DM_DEV_STATUS");
        if status.target_count() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "raid1 target never reported ready"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut file = dev.open_rw().expect("open");
    let pattern = [0x77u8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);

    // An idle raid1 echoes its table back byte for byte. dm-raid rebuilds
    // the parameter list from live array state rather than replaying the
    // constructor tokens, so this holds only while nothing is reshaping or
    // rebuilding — which devmap cannot initiate, since sync control and
    // rebuild indices are not exposed.
    let rows: Vec<_> = dev.table().expect("DM_TABLE_STATUS").collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].type_name(), "raid");
    assert_eq!(rows[0].to_string(), format!("0 {length} raid {written}"));

    // The INFO grammar is a different shape entirely: per-device health
    // characters packed into a single token whose length is set by the
    // device count preceding it, then sync progress and state.
    let info: Vec<_> = dev.info().expect("DM_TABLE_STATUS (info)").collect();
    assert_eq!(info.len(), 1);
    let status = info[0]
        .parse::<Raid>()
        .expect("the raid info grammar must parse");
    assert_eq!(status.raid_type, "raid1");
    assert_eq!(
        status.devices.len(),
        2,
        "two mirror legs, one health char each"
    );
    assert!(
        !status.devices.contains(&DeviceHealth::Dead),
        "a freshly built mirror has no failed leg: {status:?}"
    );
    assert_eq!(status.sync_total, length, "sync covers the whole array");
    assert_eq!(status.mismatches, 0);
    // Parsing is faithful: the value renders back to the kernel's line.
    assert_eq!(info[0].to_string(), format!("0 {length} raid {status}"));
}
