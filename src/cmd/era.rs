// SPDX-License-Identifier: Apache-2.0

//! The `era` persona — era-tools-equivalent operations on a dm-era
//! metadata device, via [`devmap_persistent`].

use std::fs::File;

use anyhow::{Context as _, Result, bail};
use devmap_persistent::{check, era_xml};

use crate::cli::{EraCmd, EraDump};

pub(crate) fn run(cmd: EraCmd) -> Result<()> {
    match cmd {
        EraCmd::Dump(a) => dump(&a),
        EraCmd::Check(a) => run_check(&a),
    }
}

fn run_check(a: &EraDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let report =
        check::check_era(&file).with_context(|| format!("check {}", a.metadata.display()))?;
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

fn dump(a: &EraDump) -> Result<()> {
    let file = File::open(&a.metadata).with_context(|| format!("open {}", a.metadata.display()))?;
    let xml = era_xml::dump(&file)
        .with_context(|| format!("read era metadata from {}", a.metadata.display()))?;
    print!("{xml}");
    Ok(())
}
