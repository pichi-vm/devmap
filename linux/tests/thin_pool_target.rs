// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for `thin-pool`/`thin`: provisioning a thin
//! volume is entirely message-driven (`create_thin`), exercising
//! `Device::message` end-to-end alongside both `Target` variants.

mod common;

use std::io::{Read, Seek, SeekFrom, Write};

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap_linux::targets::{Thin, ThinPool, thin, thin_pool};

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
            ThinPool::builder(metadata_device.id(), data_device.id(), 128, 32).build(),
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
            Thin {
                pool: pool_removed.id(),
                dev_id: 0,
                external_origin: None,
            },
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

    // The thin volume reports how much it has actually provisioned, which
    // is far less than its nominal size — that is the whole point of thin
    // provisioning.
    let thin_info: Vec<_> = thin_removed.info().expect("thin info").collect();
    assert_eq!(thin_info.len(), 1);
    let thin_status = thin_info[0].parse::<Thin>().expect("thin info parses");
    let thin::Info::Mapped { mapped_sectors, .. } = thin_status else {
        panic!("a live thin volume must report as mapped, got {thin_status:?}");
    };
    assert!(
        mapped_sectors > 0,
        "the 4 KiB written above must be provisioned"
    );

    // The pool's own status is the nine-field grammar, whose every field
    // the kernel terminates with a space — including the last.
    let pool_info: Vec<_> = pool_removed.info().expect("pool info").collect();
    assert_eq!(pool_info.len(), 1);
    let pool_status = pool_info[0]
        .parse::<ThinPool>()
        .expect("thin-pool info parses");
    let thin_pool::Info::Active {
        used_data_blocks,
        total_data_blocks,
        access_mode,
        needs_check,
        ..
    } = pool_status
    else {
        panic!("a healthy pool must not report Fail");
    };
    assert!(used_data_blocks > 0, "the thin write consumed a data block");
    assert!(used_data_blocks <= total_data_blocks);
    assert_eq!(access_mode, thin_pool::AccessMode::ReadWrite);
    assert!(!needs_check, "a freshly formatted pool is clean");
    // Faithful: the parsed value renders back to the kernel's own line.
    let pool_sectors = 32 * 1024 * 1024 / 512;
    assert_eq!(
        pool_info[0].to_string(),
        format!("0 {pool_sectors} thin-pool {pool_status}")
    );

    // Thin devices must be removed before their pool.
    devmap_linux::Device::from(thin_removed)
        .remove()
        .expect("remove thin device");
}
