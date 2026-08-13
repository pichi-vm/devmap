// SPDX-License-Identifier: Apache-2.0

//! Our check must agree with `thin_check` — and must catch at least one
//! class of fault that checksums alone cannot.
//!
//! Agreeing on good metadata and on obviously-corrupt metadata is
//! necessary but weak: a checker that only verified checksums would pass
//! both. The test that gives the reference-count audit its meaning tampers
//! with a *stored count* and then repairs the block's checksum, so every
//! block is individually well formed and only reconciliation can notice.
//!
//! No root needed: `thin_restore` writes into a plain file.

use std::path::{Path, PathBuf};
use std::process::Command;

use devmap_persistent::{BITMAP_CSUM_XOR, BLOCK_SIZE, check, checksum, thin};

/// Bytes of `disk_bitmap_header` before a bitmap's two-bit entries.
const BITMAP_HEADER: usize = 16;

fn have_tools() -> bool {
    Command::new("thin_restore")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The XML every fixture here is built from.
const XML: &str = r#"<superblock uuid="" time="0" transaction="1" flags="0" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="8" transaction="0" creation_time="0" snap_time="0">
    <range_mapping origin_begin="0" data_begin="0" length="8" time="0"/>
  </device>
</superblock>
"#;

fn restore(dir: &Path) -> Option<PathBuf> {
    let input = dir.join("in.xml");
    let meta = dir.join("meta.bin");
    std::fs::write(&input, XML).expect("write xml");
    std::fs::File::create(&meta)
        .and_then(|f| f.set_len(16 * 1024 * 1024))
        .expect("create metadata");
    let out = Command::new("thin_restore")
        .arg("-i")
        .arg(&input)
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
    Some(meta)
}

/// Whether `thin_check` considers `meta` sound.
fn thin_check_passes(meta: &Path) -> bool {
    Command::new("thin_check")
        .arg(meta)
        .output()
        .expect("run thin_check")
        .status
        .success()
}

#[test]
fn agrees_with_thin_check_on_sound_metadata() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(dir.path()) else {
        return;
    };
    let file = std::fs::File::open(&meta).expect("open");
    let report = check::check(&file).expect("check");

    assert!(
        report.is_clean(),
        "sound metadata must check clean: {:?}",
        report.errors
    );
    assert!(thin_check_passes(&meta), "thin_check agrees it is sound");
    // Eight data blocks were mapped, so eight must be in use.
    assert_eq!(report.data_blocks_used, 8);
    assert!(report.metadata_blocks_used > 0);
}

#[test]
fn agrees_with_thin_check_that_a_corrupt_node_is_bad() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(dir.path()) else {
        return;
    };
    let mut image = std::fs::read(&meta).expect("read");
    let superblock = thin::Superblock::read(image.as_slice()).expect("superblock");

    // Damage the top-level mapping tree node.
    let at = usize::try_from(superblock.data_mapping_root).expect("fits") * BLOCK_SIZE + 100;
    image[at] ^= 0xFF;
    std::fs::write(&meta, &image).expect("write back");

    let file = std::fs::File::open(&meta).expect("open");
    let report = check::check(&file).expect("check still produces a report");
    assert!(!report.is_clean(), "a damaged node must be reported");
    assert!(!thin_check_passes(&meta), "thin_check agrees it is bad");
}

#[test]
fn catches_a_reference_count_that_checksums_cannot() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(dir.path()) else {
        return;
    };
    let mut image = std::fs::read(&meta).expect("read");
    let superblock = thin::Superblock::read(image.as_slice()).expect("superblock");

    // Find the metadata space map's first bitmap block, then rewrite the
    // entry for block 0 — the superblock — from one reference to two.
    let sm = devmap_persistent::space_map::SpaceMap::open(
        image.as_slice(),
        superblock.metadata_sm,
        devmap_persistent::space_map::Index::Inline,
    )
    .expect("open metadata space map");
    let bitmap = usize::try_from(sm.index[0].blocknr).expect("fits") * BLOCK_SIZE;
    let data = bitmap + BITMAP_HEADER;

    // Entry n lives at little-endian bits 2n (high) and 2n+1 (low). For
    // block 0 that is bits 0 and 1: count 1 is `01`, count 2 is `10`.
    assert_eq!(
        image[data] & 0b11,
        0b10,
        "block 0 starts with one reference"
    );
    image[data] = (image[data] & !0b11) | 0b01;

    // Repair the checksum, so the block is structurally beyond reproach and
    // only a reference-count audit can object.
    let block = &mut image[bitmap..bitmap + BLOCK_SIZE];
    let fixed = checksum(block, BITMAP_CSUM_XOR);
    block[0..4].copy_from_slice(&fixed.to_le_bytes());
    std::fs::write(&meta, &image).expect("write back");

    // Confirm the tampering really is checksum-clean: reading the bitmap
    // must succeed, so nothing short of reconciliation would notice.
    let file = std::fs::File::open(&meta).expect("open");
    let reread = devmap_persistent::space_map::SpaceMap::open(
        &file,
        superblock.metadata_sm,
        devmap_persistent::space_map::Index::Inline,
    )
    .expect("the tampered bitmap still validates");
    assert_eq!(
        reread.ref_count(&file, 0).expect("ref_count"),
        2,
        "the stored count now disagrees with reality"
    );

    let report = check::check(&file).expect("check");
    assert!(
        !report.is_clean(),
        "the audit must catch a count no checksum can"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("metadata block 0") && e.contains("space map says 2")),
        "the report should name the offending block and counts: {:?}",
        report.errors
    );
}

#[test]
fn a_superblock_that_will_not_parse_is_a_hard_error() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(dir.path()) else {
        return;
    };
    let mut image = std::fs::read(&meta).expect("read");
    image[48] ^= 0xFF;
    std::fs::write(&meta, &image).expect("write back");

    // With no readable superblock there is nothing to check against, so
    // this is an error rather than a report full of findings.
    let file = std::fs::File::open(&meta).expect("open");
    assert!(check::check(&file).is_err());
    assert!(!thin_check_passes(&meta), "thin_check agrees");
}
