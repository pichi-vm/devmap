// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `dm-raid`: a minimal `raid1` (mirror) over
//! two loop devices, with no dedicated metadata devices.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap::targets::Raid;
use devmap::targets::raid::{DevicePair, Type};

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
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .builder()
        .add(
            0,
            16 * 1024 * 1024 / 512,
            Raid::new(
                Type::Raid1,
                128,
                vec![
                    DevicePair::data_only(disk0_device.id()),
                    DevicePair::data_only(disk1_device.id()),
                ],
            ),
        )
        .expect("add raid")
        .load()
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // Wait for the initial sync to at least start reporting via status
    // (raid1 is usable immediately, but give the personality a moment to
    // initialize before exercising it).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = removed.status().expect("DM_DEV_STATUS");
        if status.target_count() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "raid1 target never reported ready"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let minor = removed.id().minor();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{minor}"))
        .expect("open");
    let pattern = [0x77u8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);
}
