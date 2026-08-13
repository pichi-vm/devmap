// SPDX-License-Identifier: Apache-2.0

//! The `cache` persona — cache-tools-equivalent operations on a dm-cache
//! metadata device, via [`devmap_persistent`].

use std::fs::File;

use anyhow::{Context as _, Result, bail};
use devmap_persistent::{cache_xml, check};

use crate::cli::{CacheCmd, CacheDump};

pub(crate) fn run(cmd: CacheCmd) -> Result<()> {
    match cmd {
        CacheCmd::Dump(a) => dump(&a),
        CacheCmd::Check(a) => run_check(&a),
    }
}

fn run_check(a: &CacheDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let report =
        check::check_cache(&file).with_context(|| format!("check {}", a.metadata.display()))?;
    for error in &report.errors {
        eprintln!("devmap: {error}");
    }
    if report.is_clean() {
        println!("{}: metadata is consistent", a.metadata.display());
        println!("  Metadata blocks in use: {}", report.metadata_blocks_used);
        Ok(())
    } else {
        bail!("{} problem(s) found", report.errors.len())
    }
}

fn dump(a: &CacheDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let xml = cache_xml::dump(&file)
        .with_context(|| format!("read cache metadata from {}", a.metadata.display()))?;
    print!("{xml}");
    Ok(())
}
