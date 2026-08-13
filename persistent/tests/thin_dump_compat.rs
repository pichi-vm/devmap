// SPDX-License-Identifier: Apache-2.0

//! Our thin XML must be byte-identical to `thin_dump`'s.
//!
//! This is not a formatting preference. `thin_restore` reads this XML to
//! rebuild a pool, so it is the interchange format for metadata backups —
//! output that merely *looks* right but differs is a dialect the standard
//! tools cannot consume.
//!
//! `thin_restore` writes into a plain file, so no root is needed.

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use devmap_persistent::{thin, thin_xml};

fn have_tools() -> bool {
    Command::new("thin_restore")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build metadata from `xml` with `thin_restore`, returning its path.
fn restore(dir: &Path, xml: &str) -> Option<std::path::PathBuf> {
    let input = dir.join("in.xml");
    let meta = dir.join("meta.bin");
    std::fs::write(&input, xml).expect("write xml");
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

/// What `thin_dump` prints for `meta`.
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
    String::from_utf8(out.stdout).expect("thin_dump output is utf8")
}

/// Restore `xml`, dump it both ways, and require the two to agree.
fn assert_matches_thin_dump(xml: &str) {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(dir.path(), xml) else {
        return;
    };

    let expected = thin_dump(&meta);
    let file = std::fs::File::open(&meta).expect("open metadata");
    let ours = thin_xml::dump(&file).expect("dump");
    assert_eq!(ours, expected, "our XML must match thin_dump byte for byte");
}

#[test]
fn matches_thin_dump_for_ranges_and_singles() {
    assert_matches_thin_dump(
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
fn matches_thin_dump_for_a_pool_with_no_devices() {
    assert_matches_thin_dump(
        r#"<superblock uuid="" time="0" transaction="0" flags="0" version="2" data_block_size="128" nr_data_blocks="1024">
</superblock>
"#,
    );
}

#[test]
fn matches_thin_dump_across_a_multi_node_tree() {
    // Enough mappings to push the per-device btree past a single leaf, so
    // the walk has to descend internal nodes and stitch leaves together in
    // key order. A single-leaf fixture would never exercise that.
    let mut xml = String::from(
        r#"<superblock uuid="" time="0" transaction="1" flags="0" version="2" data_block_size="128" nr_data_blocks="65536">
  <device dev_id="1" mapped_blocks="2000" transaction="0" creation_time="0" snap_time="0">
"#,
    );
    // Deliberately non-contiguous so they cannot all coalesce into one run.
    for i in 0..2000u64 {
        let _ = writeln!(
            xml,
            "    <single_mapping origin_block=\"{}\" data_block=\"{}\" time=\"0\"/>",
            i * 2,
            i * 3
        );
    }
    xml.push_str("  </device>\n</superblock>\n");
    assert_matches_thin_dump(&xml);
}

#[test]
fn reads_the_space_maps_of_real_metadata() {
    if !have_tools() {
        eprintln!("skip: thin-provisioning-tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(
        dir.path(),
        r#"<superblock uuid="" time="0" transaction="1" flags="0" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="4" transaction="0" creation_time="0" snap_time="0">
    <range_mapping origin_begin="0" data_begin="0" length="4" time="0"/>
  </device>
</superblock>
"#,
    ) else {
        return;
    };
    let file = std::fs::File::open(&meta).expect("open metadata");
    let superblock = thin::Superblock::read(&file).expect("superblock");
    let (data, metadata) = thin::space_maps(&file, &superblock).expect("space maps");

    // Four data blocks were mapped, so four must be allocated.
    assert_eq!(data.root.nr_allocated, 4);
    assert_eq!(data.root.nr_blocks, 4096);

    // Those four data blocks must each read back a reference count of one,
    // which exercises the bitmap's two-bit packing against real bytes.
    for block in 0..4 {
        assert_eq!(
            data.ref_count(&file, block).expect("ref_count"),
            1,
            "data block {block} is referenced once"
        );
    }
    // A block nothing maps must read zero.
    assert_eq!(data.ref_count(&file, 100).expect("ref_count"), 0);

    // The metadata map's own blocks are in use, and its inline index
    // resolved — a wrong index layout would have failed to open at all.
    assert!(metadata.root.nr_allocated > 0);
    assert_ne!(metadata.index.len(), 0, "inline index resolved");
    assert_eq!(
        metadata.ref_count(&file, 0).expect("ref_count"),
        1,
        "the superblock is referenced"
    );
}
