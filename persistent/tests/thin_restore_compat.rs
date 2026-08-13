// SPDX-License-Identifier: Apache-2.0

//! Metadata we write must be indistinguishable from `thin_restore`'s.
//!
//! Two independent gates, because either alone is weak:
//!
//! - `thin_check` must accept what we wrote. This catches structural and
//!   reference-count faults, judged by the reference implementation rather
//!   than by our own reader agreeing with our own writer.
//! - `thin_dump` of our metadata must equal `thin_dump` of `thin_restore`'s
//!   metadata built from the same input. This catches content faults —
//!   a dropped mapping or a mangled timestamp — that still produce
//!   structurally valid metadata.
//!
//! The comparison is dump-to-dump rather than against the input XML,
//! because `thin_dump` legitimately normalises: it drops the input-only
//! `flags` attribute and re-coalesces mappings into ranges.
//!
//! No root needed; everything is file-backed.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use devmap_persistent::{check, restore, xml};

/// Metadata device size for the fixtures, in bytes.
const METADATA_BYTES: u64 = 32 * 1024 * 1024;

fn have_tools() -> bool {
    Command::new("thin_restore")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build metadata from `input` with the real `thin_restore`.
fn reference_restore(dir: &Path, input: &Path) -> Option<PathBuf> {
    let meta = dir.join("reference.bin");
    std::fs::File::create(&meta)
        .and_then(|f| f.set_len(METADATA_BYTES))
        .expect("create metadata");
    let out = Command::new("thin_restore")
        .arg("-i")
        .arg(input)
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

fn thin_dump(meta: &Path) -> String {
    let out = Command::new("thin_dump")
        .arg(meta)
        .output()
        .expect("run thin_dump");
    assert!(
        out.status.success(),
        "thin_dump failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn thin_check_passes(meta: &Path) -> bool {
    Command::new("thin_check")
        .arg(meta)
        .output()
        .expect("run thin_check")
        .status
        .success()
}

/// Restore `xml_text` both ways and require the results to agree.
fn assert_restore_matches(xml_text: &str) {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("in.xml");
    std::fs::write(&input, xml_text).expect("write xml");
    let Some(reference) = reference_restore(dir.path(), &input) else {
        return;
    };

    // Build the same pool with our writer.
    let pool = xml::parse(xml_text).expect("parse the XML");
    let ours = dir.path().join("ours.bin");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ours)
        .expect("create ours");
    file.set_len(METADATA_BYTES).expect("size ours");
    restore::restore(
        &pool,
        &mut file,
        METADATA_BYTES / devmap_persistent::BLOCK_SIZE as u64,
    )
    .expect("restore");
    drop(file);

    assert!(
        thin_check_passes(&ours),
        "thin_check must accept the metadata we wrote"
    );
    assert_eq!(
        thin_dump(&ours),
        thin_dump(&reference),
        "our metadata must dump identically to thin_restore's"
    );

    // And our own checker must agree it is sound, including the
    // reference-count reconciliation.
    let file = std::fs::File::open(&ours).expect("open ours");
    let report = check::check(&file).expect("check");
    assert!(report.is_clean(), "our own check: {:?}", report.errors);
}

#[test]
fn matches_thin_restore_for_ranges_and_singles() {
    assert_restore_matches(
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
    );
}

#[test]
fn matches_thin_restore_for_an_empty_pool() {
    assert_restore_matches(
        r#"<superblock uuid="" time="0" transaction="0" flags="0" version="2" data_block_size="128" nr_data_blocks="1024">
</superblock>
"#,
    );
}

#[test]
fn matches_thin_restore_when_a_data_block_is_widely_shared() {
    // Four devices pointing at one data block gives it a reference count of
    // four, which cannot fit the two-bit bitmap and must spill into the
    // overflow btree. A writer that ignored the overflow would still
    // produce a structurally valid pool, so thin_check is what catches it.
    assert_restore_matches(
        r#"<superblock uuid="" time="0" transaction="1" flags="0" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="0" data_block="42" time="0"/>
  </device>
  <device dev_id="2" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="0" data_block="42" time="0"/>
  </device>
  <device dev_id="3" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="0" data_block="42" time="0"/>
  </device>
  <device dev_id="4" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="0" data_block="42" time="0"/>
  </device>
</superblock>
"#,
    );
}

#[test]
fn matches_thin_restore_across_a_multi_level_tree() {
    // Far more mappings than one leaf holds, so the builder has to add
    // internal levels; deliberately non-contiguous so nothing coalesces
    // away.
    use std::fmt::Write as _;
    let mut xml = String::from(
        r#"<superblock uuid="" time="0" transaction="1" flags="0" version="2" data_block_size="128" nr_data_blocks="200000">
  <device dev_id="1" mapped_blocks="5000" transaction="0" creation_time="0" snap_time="0">
"#,
    );
    for i in 0..5000u64 {
        let _ = writeln!(
            xml,
            r#"    <single_mapping origin_block="{}" data_block="{}" time="0"/>"#,
            i * 3,
            i * 2
        );
    }
    xml.push_str("  </device>\n</superblock>\n");
    assert_restore_matches(&xml);
}

#[test]
fn refuses_a_metadata_device_too_small_to_hold_the_pool() {
    // Running out of space must be an error, never a truncated pool: a
    // half-written pool that still parsed would be far worse than a
    // refusal.
    let pool = xml::parse(
        r#"<superblock uuid="" time="0" transaction="1" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="0" data_block="0" time="0"/>
  </device>
</superblock>"#,
    )
    .expect("parse");

    let mut out = Cursor::new(vec![0u8; devmap_persistent::BLOCK_SIZE * 4]);
    assert!(
        restore::restore(&pool, &mut out, 4).is_err(),
        "four blocks cannot hold a pool"
    );
}
