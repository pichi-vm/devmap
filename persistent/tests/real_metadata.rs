// SPDX-License-Identifier: Apache-2.0

//! Read metadata that the real `thin_restore` produced.
//!
//! Unit tests build their own blocks, so they would pass even if the
//! checksum convention or the node layout were subtly wrong. This reads
//! bytes written by thin-provisioning-tools itself, which is what actually
//! pins the format.
//!
//! `thin_restore` writes into a plain file, so no root is needed. Skips
//! cleanly when the tools are absent.

use std::path::Path;
use std::process::Command;

use devmap_persistent::block::{le32, le64, read_validated};
use devmap_persistent::btree::ValueSize;
use devmap_persistent::{BLOCK_SIZE, THIN_SUPERBLOCK_CSUM_XOR, btree};

/// Thin superblock field offsets, from `struct thin_disk_superblock`.
const OFF_MAGIC: usize = 32;
const OFF_VERSION: usize = 40;
const OFF_TRANS_ID: usize = 48;
const OFF_DATA_MAPPING_ROOT: usize = 320;
const OFF_DETAILS_ROOT: usize = 328;
const OFF_DATA_BLOCK_SIZE: usize = 336;

/// `THIN_SUPERBLOCK_MAGIC`.
const THIN_MAGIC: u64 = 27_022_010;

fn have_tools() -> bool {
    Command::new("thin_restore")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build metadata with `thin_restore` from XML describing two thin devices.
fn build_metadata(dir: &Path) -> Option<Vec<u8>> {
    let xml = dir.join("in.xml");
    let meta = dir.join("meta.bin");
    std::fs::write(
        &xml,
        r#"<superblock uuid="" time="1" transaction="2" flags="0" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="3" transaction="0" creation_time="0" snap_time="1">
    <range_mapping origin_begin="0" data_begin="0" length="2" time="0"/>
    <single_mapping origin_block="5" data_block="7" time="1"/>
  </device>
  <device dev_id="2" mapped_blocks="1" transaction="1" creation_time="1" snap_time="1">
    <single_mapping origin_block="0" data_block="9" time="1"/>
  </device>
</superblock>
"#,
    )
    .expect("write xml");
    std::fs::File::create(&meta)
        .and_then(|f| f.set_len(16 * 1024 * 1024))
        .expect("create metadata file");

    let out = Command::new("thin_restore")
        .arg("-i")
        .arg(&xml)
        .arg("-o")
        .arg(&meta)
        .output()
        .expect("run thin_restore");
    if !out.status.success() {
        eprintln!(
            "skip: thin_restore failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(std::fs::read(&meta).expect("read metadata"))
}

#[test]
fn reads_a_superblock_thin_restore_wrote() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(image) = build_metadata(dir.path()) else {
        return;
    };

    // If the checksum convention were wrong this would fail outright — it
    // is the whole reason this test reads real bytes.
    let sb = read_validated(image.as_slice(), 0, THIN_SUPERBLOCK_CSUM_XOR)
        .expect("superblock must validate");

    assert_eq!(le64(&sb, OFF_MAGIC), THIN_MAGIC, "thin superblock magic");
    assert_eq!(le32(&sb, OFF_VERSION), 2);
    assert_eq!(le64(&sb, OFF_TRANS_ID), 2, "transaction from the XML");
    assert_eq!(
        le32(&sb, OFF_DATA_BLOCK_SIZE),
        128,
        "data_block_size from the XML"
    );
}

#[test]
fn walks_the_device_details_tree_thin_restore_wrote() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(image) = build_metadata(dir.path()) else {
        return;
    };
    let sb = read_validated(image.as_slice(), 0, THIN_SUPERBLOCK_CSUM_XOR).expect("superblock");

    // The details tree is keyed by dev_id; the XML declared devices 1 and 2.
    let root = le64(&sb, OFF_DETAILS_ROOT);
    let details =
        btree::collect(image.as_slice(), root, 16, ValueSize(24)).expect("walk device details");
    let ids: Vec<u64> = details.iter().map(|(k, _)| *k).collect();
    assert_eq!(ids, [1, 2], "one entry per device, in key order");

    // device_details is 24 bytes: mapped_blocks, transaction_id,
    // creation_time, snapshotted_time.
    let (_, first) = &details[0];
    assert_eq!(first.len(), 24, "device_details value size");
    assert_eq!(le64(first, 0), 3, "device 1 has 3 mapped blocks");
}

#[test]
fn walks_the_two_level_mapping_tree_thin_restore_wrote() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(image) = build_metadata(dir.path()) else {
        return;
    };
    let sb = read_validated(image.as_slice(), 0, THIN_SUPERBLOCK_CSUM_XOR).expect("superblock");

    // The top level maps dev_id -> the root of that device's mapping tree.
    let top = le64(&sb, OFF_DATA_MAPPING_ROOT);
    let devices = btree::collect(image.as_slice(), top, 16, ValueSize(8)).expect("walk top level");
    let ids: Vec<u64> = devices.iter().map(|(k, _)| *k).collect();
    assert_eq!(ids, [1, 2]);

    // Device 1's own tree maps origin block -> (data block, time), packed
    // as a single u64: the low 24 bits are the time.
    let dev1_root = le64(&devices[0].1, 0);
    let mappings =
        btree::collect(image.as_slice(), dev1_root, 16, ValueSize(8)).expect("walk device 1");
    let origins: Vec<u64> = mappings.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        origins,
        [0, 1, 5],
        "the range mapping expands to blocks 0 and 1, plus the single mapping at 5"
    );

    let data_block = |value: &[u8]| le64(value, 0) >> 24;
    assert_eq!(data_block(&mappings[0].1), 0, "origin 0 -> data 0");
    assert_eq!(data_block(&mappings[1].1), 1, "origin 1 -> data 1");
    assert_eq!(data_block(&mappings[2].1), 7, "origin 5 -> data 7");
}

#[test]
fn rejects_metadata_we_corrupt() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(mut image) = build_metadata(dir.path()) else {
        return;
    };
    // Flip a byte inside the superblock; the checksum must catch it.
    image[OFF_TRANS_ID] ^= 0xFF;
    assert!(
        read_validated(image.as_slice(), 0, THIN_SUPERBLOCK_CSUM_XOR).is_err(),
        "a corrupted superblock must not validate"
    );

    // And a block asked for as the wrong structure must be rejected too.
    let clean = build_metadata(dir.path()).expect("rebuild");
    assert!(
        read_validated(clean.as_slice(), 0, devmap_persistent::BTREE_CSUM_XOR).is_err(),
        "the superblock is not a btree node"
    );
    assert_eq!(clean.len() % BLOCK_SIZE, 0, "metadata is whole blocks");
}
