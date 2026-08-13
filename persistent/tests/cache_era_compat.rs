// SPDX-License-Identifier: Apache-2.0

//! Our cache and era dumps must match `cache_dump` and `era_dump`.
//!
//! These exercise the structures thin never touches — `dm-array` for the
//! cache mapping and hint arrays and the era array, and `dm-bitset` for
//! the cache's version-2 dirty bits and era's writesets. A cache dump that
//! reports the right mappings but the wrong dirty flags would still look
//! plausible, so byte-comparison against the reference tools is what
//! settles it.
//!
//! No root needed; the restore tools write into plain files.

use std::path::{Path, PathBuf};
use std::process::Command;

use devmap_persistent::{cache_xml, era_xml};

/// Whether `tool` is installed.
fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Restore `xml` with `tool`, returning the metadata path.
fn restore(dir: &Path, tool: &str, xml: &str) -> Option<PathBuf> {
    let input = dir.join("in.xml");
    let meta = dir.join("meta.bin");
    std::fs::write(&input, xml).expect("write xml");
    std::fs::File::create(&meta)
        .and_then(|f| f.set_len(16 * 1024 * 1024))
        .expect("create metadata");
    let out = Command::new(tool)
        .arg("-i")
        .arg(&input)
        .arg("-o")
        .arg(&meta)
        .output()
        .expect("run restore");
    if !out.status.success() {
        eprintln!(
            "skip: {tool} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(meta)
}

/// What `tool` dumps for `meta`.
fn reference_dump(tool: &str, meta: &Path) -> String {
    let out = Command::new(tool).arg(meta).output().expect("run dump");
    assert!(
        out.status.success(),
        "{tool} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

#[test]
fn matches_cache_dump() {
    if !have("cache_restore") {
        eprintln!("skip: cache tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    // A dirty mapping among clean ones: on version-2 metadata the dirty
    // flag comes from a separate bitset, so getting it right proves the
    // bitset decode rather than just the mapping array.
    let Some(meta) = restore(
        dir.path(),
        "cache_restore",
        r#"<superblock uuid="" block_size="128" nr_cache_blocks="1024" policy="smq" hint_width="4">
  <mappings>
    <mapping cache_block="0" origin_block="0" dirty="false"/>
    <mapping cache_block="1" origin_block="17" dirty="true"/>
    <mapping cache_block="2" origin_block="99" dirty="false"/>
  </mappings>
</superblock>
"#,
    ) else {
        return;
    };

    let file = std::fs::File::open(&meta).expect("open");
    assert_eq!(
        cache_xml::dump(&file).expect("dump"),
        reference_dump("cache_dump", &meta),
        "our cache XML must match cache_dump byte for byte"
    );
}

#[test]
fn matches_era_dump() {
    if !have("era_restore") {
        eprintln!("skip: era tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(
        dir.path(),
        "era_restore",
        r#"<superblock uuid="" block_size="128" nr_blocks="512" current_era="1">
  <writeset era="1" nr_bits="512">
    <bit block="0" value="true"/>
    <bit block="5" value="true"/>
  </writeset>
  <era_array>
    <era block="0" era="1"/>
    <era block="1" era="0"/>
  </era_array>
</superblock>
"#,
    ) else {
        return;
    };

    let file = std::fs::File::open(&meta).expect("open");
    assert_eq!(
        era_xml::dump(&file).expect("dump"),
        reference_dump("era_dump", &meta),
        "our era XML must match era_dump byte for byte"
    );
}

#[test]
fn a_cache_superblock_is_not_an_era_superblock() {
    // The two share a block layer but not a magic; confusing them would
    // read one target's roots out of the other's fields.
    if !have("cache_restore") {
        eprintln!("skip: cache tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(meta) = restore(
        dir.path(),
        "cache_restore",
        r#"<superblock uuid="" block_size="128" nr_cache_blocks="16" policy="smq" hint_width="4">
  <mappings>
  </mappings>
</superblock>
"#,
    ) else {
        return;
    };
    let file = std::fs::File::open(&meta).expect("open");
    assert!(
        devmap_persistent::era::Superblock::read(&file).is_err(),
        "cache metadata must not parse as era"
    );
    assert!(devmap_persistent::cache::Superblock::read(&file).is_ok());
}
