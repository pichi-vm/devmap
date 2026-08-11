// SPDX-License-Identifier: Apache-2.0

//! Command handlers, one module per object.

mod dm;
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
    }
}
