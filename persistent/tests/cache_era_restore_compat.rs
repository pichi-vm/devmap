// SPDX-License-Identifier: Apache-2.0

//! Cache and era metadata we write must satisfy the reference tools.
//!
//! Two gates per target, matching how thin's write path is judged:
//! `cache_check`/`era_check` must accept what we produce, and dumping it
//! must report back exactly the content we asked for. The second gate is
//! what catches a writer that lays out valid-but-wrong metadata.
//!
//! No root needed.

use std::path::Path;
use std::process::Command;

use devmap_persistent::cache::Mapping;
use devmap_persistent::restore::{CachePool, EraPool, restore_cache, restore_era};

/// Metadata device size for these fixtures, in blocks.
const METADATA_BLOCKS: u64 = 4096;

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A file-backed metadata device of [`METADATA_BLOCKS`] blocks.
fn scratch(dir: &Path) -> (std::path::PathBuf, std::fs::File) {
    let meta = dir.join("ours.bin");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&meta)
        .expect("create metadata");
    file.set_len(METADATA_BLOCKS * devmap_persistent::BLOCK_SIZE as u64)
        .expect("size metadata");
    (meta, file)
}

fn run(tool: &str, meta: &Path) -> (bool, String) {
    let out = Command::new(tool).arg(meta).output().expect("run tool");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn cache_tools_accept_the_metadata_we_write() {
    if !have("cache_restore") {
        eprintln!("skip: cache tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (meta, mut file) = scratch(dir.path());

    let cache = CachePool {
        block_size: 128,
        nr_cache_blocks: 1024,
        policy: "smq".to_owned(),
        hint_width: 4,
        mappings: vec![
            Mapping {
                cache_block: 0,
                origin_block: 0,
                dirty: false,
            },
            // A dirty mapping exercises the version-2 dirty bitset on the
            // way out as well as the way back in.
            Mapping {
                cache_block: 1,
                origin_block: 17,
                dirty: true,
            },
            Mapping {
                cache_block: 900,
                origin_block: 4242,
                dirty: false,
            },
        ],
    };
    restore_cache(&cache, &mut file, METADATA_BLOCKS).expect("restore");
    drop(file);

    let (ok, _) = run("cache_check", &meta);
    assert!(ok, "cache_check must accept what we wrote");

    // And the content must survive the round trip, dirtiness included.
    let (ok, dumped) = run("cache_dump", &meta);
    assert!(ok, "cache_dump");
    assert!(
        dumped.contains(r#"<mapping cache_block="1" origin_block="17" dirty="true"/>"#),
        "the dirty mapping must round-trip: {dumped}"
    );
    assert!(
        dumped.contains(r#"<mapping cache_block="900" origin_block="4242" dirty="false"/>"#),
        "a mapping late in the array must round-trip: {dumped}"
    );
    // Our own audit must agree it is sound.
    let file = std::fs::File::open(&meta).expect("open");
    let report = devmap_persistent::check::check_cache(&file).expect("check");
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn era_tools_accept_the_metadata_we_write() {
    if !have("era_restore") {
        eprintln!("skip: era tools not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (meta, mut file) = scratch(dir.path());

    let mut bits = vec![false; 512];
    bits[0] = true;
    bits[5] = true;
    let mut eras = vec![0u32; 512];
    eras[0] = 1;

    let era = EraPool {
        block_size: 128,
        nr_blocks: 512,
        current_era: 1,
        writesets: vec![(1, bits)],
        era_array: eras,
    };
    restore_era(&era, &mut file, METADATA_BLOCKS).expect("restore");
    drop(file);

    let (ok, _) = run("era_check", &meta);
    assert!(ok, "era_check must accept what we wrote");

    let (ok, dumped) = run("era_dump", &meta);
    assert!(ok, "era_dump");
    assert!(
        dumped.contains(r#"<bit block="0" value="true"/>"#)
            && dumped.contains(r#"<bit block="5" value="true"/>"#),
        "the set bits must round-trip"
    );
    assert!(
        dumped.contains(r#"<era block="0" era="1"/>"#),
        "the era array must round-trip"
    );
    let file = std::fs::File::open(&meta).expect("open");
    let report = devmap_persistent::check::check_era(&file).expect("check");
    assert!(report.is_clean(), "{:?}", report.errors);
}

#[test]
fn a_cache_block_beyond_the_cache_is_refused() {
    // Writing it would corrupt whatever follows the mapping array.
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut file) = scratch(dir.path());
    let cache = CachePool {
        block_size: 128,
        nr_cache_blocks: 8,
        policy: "smq".to_owned(),
        hint_width: 4,
        mappings: vec![Mapping {
            cache_block: 99,
            origin_block: 0,
            dirty: false,
        }],
    };
    assert!(restore_cache(&cache, &mut file, METADATA_BLOCKS).is_err());
}
