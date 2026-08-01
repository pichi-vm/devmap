// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `thin-pool`/`thin`: provisioning a thin
//! volume is entirely message-driven (`create_thin`), exercising
//! `Device::message` end-to-end alongside both `Target` variants.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap::targets::{Thin, ThinPool};

#[test]
fn thin_pool_provisions_a_volume_via_message_and_reads_writes() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-thin-pool");

    let metadata = LoopDevice::create("thinpool-meta", 8 * 1024 * 1024);
    let data = LoopDevice::create("thinpool-data", 32 * 1024 * 1024);
    let metadata_device = control.by_node(&metadata.path).expect("by_node metadata");
    let data_device = control.by_node(&data.path).expect("by_node data");

    let pool_name = format!("devmap-test-thinpool-{}", std::process::id());
    let pool_removed = control.create(&pool_name).expect("DM_DEV_CREATE pool");
    pool_removed
        .builder()
        .add(
            0,
            32 * 1024 * 1024 / 512,
            ThinPool::builder(metadata_device.id(), data_device.id(), 128, 32)
                .build()
                .expect("build pool"),
        )
        .expect("add thin-pool")
        .load()
        .expect("DM_TABLE_LOAD pool");
    pool_removed.resume().expect("resume pool");

    let reply = pool_removed
        .message(0, "create_thin 0")
        .expect("create_thin message");
    assert_eq!(
        reply, None,
        "create_thin produces no reply string on success"
    );

    let thin_name = format!("devmap-test-thin-{}", std::process::id());
    let thin_removed = control.create(&thin_name).expect("DM_DEV_CREATE thin");
    thin_removed
        .builder()
        .add(
            0,
            16 * 1024 * 1024 / 512,
            Thin::new(pool_removed.id(), 0, None).expect("valid thin"),
        )
        .expect("add thin")
        .load()
        .expect("DM_TABLE_LOAD thin");
    thin_removed.resume().expect("resume thin");

    let minor = thin_removed.id().minor();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/dm-{minor}"))
        .expect("open");
    let pattern = [0x33u8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern);
    drop(file); // DM_DEV_REMOVE fails with EBUSY while the device node is open

    // Thin devices must be removed before their pool.
    devmap::Device::from(thin_removed)
        .remove()
        .expect("remove thin device");
}
