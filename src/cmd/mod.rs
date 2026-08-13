// SPDX-License-Identifier: Apache-2.0

//! Command handlers, one module per object.

mod cache;
mod crypt;
mod dm;
mod era;
mod integrity;
mod links;
mod snapshot;
mod thin;
mod verity;
mod zoned;

use anyhow::Result;

use crate::cli::{Cli, Object};

/// Dispatch a parsed command line to its handler.
pub(crate) fn run(cli: Cli) -> Result<()> {
    match cli.object {
        Object::Dm(cmd) => dm::run(cmd),
        Object::Verity(cmd) => verity::run(cmd),
        Object::Zoned(cmd) => zoned::run(cmd),
        Object::Integrity(cmd) => integrity::run(cmd),
        Object::Crypt(cmd) => crypt::run(cmd),
        Object::Snapshot(cmd) => snapshot::run(cmd),
        Object::Thin(cmd) => thin::run(cmd),
        Object::Cache(cmd) => cache::run(cmd),
        Object::Era(cmd) => era::run(cmd),
        Object::InstallLinks(a) => links::run(&a),
    }
}
