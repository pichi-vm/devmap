// SPDX-License-Identifier: Apache-2.0

//! The `era` persona — era-tools-equivalent operations on a dm-era
//! metadata device, via [`devmap_persistent`].

use std::fs::File;

use anyhow::{Context as _, Result};
use devmap_persistent::era_xml;

use crate::cli::{EraCmd, EraDump};

pub(crate) fn run(cmd: EraCmd) -> Result<()> {
    match cmd {
        EraCmd::Dump(a) => dump(&a),
    }
}

fn dump(a: &EraDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let xml = era_xml::dump(&file)
        .with_context(|| format!("read era metadata from {}", a.metadata.display()))?;
    print!("{xml}");
    Ok(())
}
