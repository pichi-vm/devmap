// SPDX-License-Identifier: Apache-2.0

//! `devmap` — a device-mapper multitool.
//!
//! Canonical form is `devmap <object> <verb>` (`dm`, and the setup
//! personas as they land). Symlinking a legacy tool name to this binary
//! makes it behave like that tool: `ln -s devmap dmsetup` then runs
//! `dmsetup create …` as `devmap dm create …` (see [`multicall`]).

// The CLI's docs and clap help mention many bare tool and target names
// (dmsetup, veritysetup, thin-pool, …) that read fine unquoted.
#![allow(clippy::doc_markdown)]

mod cli;
mod cmd;
mod multicall;
mod table_input;

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let argv = multicall::normalize(std::env::args_os().collect());
    let cli = cli::Cli::parse_from(argv);
    match cmd::run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("devmap: {e:#}");
            ExitCode::FAILURE
        }
    }
}
