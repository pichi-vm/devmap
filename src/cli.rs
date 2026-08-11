// SPDX-License-Identifier: Apache-2.0

//! The `devmap` command tree. Noun-first: `devmap <object> <verb>`. The
//! multi-call shim in [`crate::multicall`] maps legacy tool names
//! (`dmsetup`, …) onto these objects.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "devmap", version, about = "A device-mapper multitool")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) object: Object,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Object {
    /// Raw device-mapper operations — the `dmsetup` layer.
    #[command(subcommand)]
    Dm(DmCmd),
}

/// The `dmsetup`-equivalent verbs.
#[derive(Subcommand, Debug)]
pub(crate) enum DmCmd {
    /// Create a device, load a table, and resume it.
    Create(Create),
    /// Stage a new inactive table without activating it.
    Reload(Reload),
    /// Remove a device.
    Remove(Name),
    /// Suspend a device (flush and queue I/O).
    Suspend(Name),
    /// Resume a device, activating any staged table.
    Resume(Name),
    /// Discard a staged inactive table.
    Clear(Name),
    /// Print the active table (`STATUSTYPE_TABLE`).
    Table(Name),
    /// Print runtime status (`STATUSTYPE_INFO`).
    Status(Name),
    /// Print device information (state, counts, dev_t).
    Info(Name),
    /// List all device-mapper devices.
    Ls,
    /// Print the devices a table depends on.
    Deps(Name),
    /// Rename a device, or set its uuid with `--setuuid`.
    Rename(Rename),
    /// Send a message to a target.
    Message(Message),
    /// Block until the device's event counter advances.
    Wait(Wait),
    /// List the target types the kernel supports.
    Targets,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Create {
    /// Device name.
    pub(crate) name: String,
    /// Table file, or `-`/omitted for stdin.
    #[arg(long)]
    pub(crate) table: Option<PathBuf>,
    /// Attach this uuid to the new device.
    #[arg(long)]
    pub(crate) uuid: Option<String>,
    /// Load the table read-only.
    #[arg(long)]
    pub(crate) readonly: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Reload {
    /// Device name.
    pub(crate) name: String,
    /// Table file, or `-`/omitted for stdin.
    #[arg(long)]
    pub(crate) table: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Name {
    /// Device name.
    pub(crate) name: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Rename {
    /// Current device name.
    pub(crate) name: String,
    /// New name, or new uuid with `--setuuid`.
    pub(crate) new_name: String,
    /// Interpret `new_name` as a uuid to attach, not a new name.
    #[arg(long)]
    pub(crate) setuuid: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Message {
    /// Device name.
    pub(crate) name: String,
    /// Sector the message targets (0 for whole-device targets).
    pub(crate) sector: u64,
    /// The message words, e.g. `create_thin 0`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub(crate) words: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct Wait {
    /// Device name.
    pub(crate) name: String,
    /// Wait for an event after this number; defaults to the current one.
    pub(crate) event_nr: Option<u32>,
}
