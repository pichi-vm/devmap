// SPDX-License-Identifier: Apache-2.0

//! The `cache` persona — cache-tools-equivalent operations on a dm-cache
//! metadata device, via [`devmap_persistent`].

use std::fs::File;

use anyhow::{Context as _, Result};
use devmap_persistent::cache_xml;

use crate::cli::{CacheCmd, CacheDump};

pub(crate) fn run(cmd: CacheCmd) -> Result<()> {
    match cmd {
        CacheCmd::Dump(a) => dump(&a),
    }
}

fn dump(a: &CacheDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let xml = cache_xml::dump(&file)
        .with_context(|| format!("read cache metadata from {}", a.metadata.display()))?;
    print!("{xml}");
    Ok(())
}
