// SPDX-License-Identifier: Apache-2.0

//! Real-kernel coverage for the single-device passthrough-style targets:
//! `delay`, `flakey`, `dust`, `unstriped`. Each wraps one loop device and
//! is verified by a plain write/read round trip through the mapped
//! device — none of these targets alter data in their default
//! configuration, they only affect timing/fault behavior.

mod common;

use common::{LoopDevice, ensure_module_loaded, open_control};
use devmap::{DelayLeg, TableLine, Target};

fn write_then_read_back(path: &str) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).expect("open mapped device");
    let pattern = [0xABu8; 4096];
    file.write_all(&pattern).expect("write");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = [0u8; 4096];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern, "data must round-trip unchanged through a passthrough target");
}

#[test]
fn delay_passes_data_through_unchanged() {
    let Some(control) = open_control() else { return };
    ensure_module_loaded("dm-delay");

    let backing = LoopDevice::create("delay", 8 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing device");

    let name = format!("devmap-test-delay-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .load_table(&[TableLine::new(
            0,
            16384,
            Target::Delay {
                read: DelayLeg::new(backing_device.id(), 0, 10),
                write: None,
                flush: None,
            },
        )])
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    write_then_read_back(&format!("/dev/dm-{minor}"));
}

#[test]
fn flakey_behaves_normally_during_the_up_interval() {
    let Some(control) = open_control() else { return };
    ensure_module_loaded("dm-flakey");

    let backing = LoopDevice::create("flakey", 8 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing device");

    let name = format!("devmap-test-flakey-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .load_table(&[TableLine::new(
            0,
            16384,
            Target::Flakey {
                device: backing_device.id(),
                offset_sectors: 0,
                up_interval_secs: 3600,
                down_interval_secs: 1,
                features: vec![],
            },
        )])
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    write_then_read_back(&format!("/dev/dm-{minor}"));
}

#[test]
fn dust_bypass_mode_passes_data_through_and_message_interface_works() {
    let Some(control) = open_control() else { return };
    ensure_module_loaded("dm-dust");

    let backing = LoopDevice::create("dust", 8 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing device");

    let name = format!("devmap-test-dust-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .load_table(&[TableLine::new(
            0,
            16384,
            Target::Dust { device: backing_device.id(), offset_sectors: 0, block_size: 512 },
        )])
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    // dust starts in "bypass" mode (all I/O passed through) until `enable`.
    let minor = removed.id().minor();
    write_then_read_back(&format!("/dev/dm-{minor}"));

    let reply = removed.message(0, "countbadblocks").expect("countbadblocks message");
    assert!(reply.is_some(), "countbadblocks should report a count string");
}

#[test]
fn unstriped_with_a_single_stripe_is_a_pure_passthrough() {
    let Some(control) = open_control() else { return };
    ensure_module_loaded("dm-unstripe");

    let backing = LoopDevice::create("unstriped", 8 * 1024 * 1024);
    let backing_device = control.by_node(&backing.path).expect("by_node backing device");

    let name = format!("devmap-test-unstriped-{}", std::process::id());
    let removed = control.create(&name).expect("DM_DEV_CREATE");
    removed
        .load_table(&[TableLine::new(
            0,
            16384,
            Target::Unstriped {
                stripes: 1,
                chunk_size_sectors: 16384,
                stripe_index: 0,
                device: backing_device.id(),
                offset_sectors: 0,
            },
        )])
        .expect("DM_TABLE_LOAD");
    removed.resume().expect("resume");

    let minor = removed.id().minor();
    write_then_read_back(&format!("/dev/dm-{minor}"));
}
