// SPDX-License-Identifier: Apache-2.0

//! The `dm` persona — `dmsetup`-equivalent operations over
//! [`devmap_linux`].

use anyhow::{Context as _, Result};

use crate::cli::{Create, DmCmd, Message, Name, Reload, Rename, Wait};
use crate::{control, table_input};

pub(crate) fn run(cmd: DmCmd) -> Result<()> {
    match cmd {
        DmCmd::Create(a) => create(&a),
        DmCmd::Reload(a) => reload(&a),
        DmCmd::Remove(a) => control::remove(&a.name),
        DmCmd::Suspend(a) => control::by_name(&a.name)?.suspend().context("suspend"),
        DmCmd::Resume(a) => control::by_name(&a.name)?.resume().context("resume"),
        DmCmd::Clear(a) => control::by_name(&a.name)?
            .clear_inactive_table()
            .context("clear"),
        DmCmd::Table(a) => table(&a),
        DmCmd::Status(a) => status(&a),
        DmCmd::Info(a) => info(&a),
        DmCmd::Ls => ls(),
        DmCmd::Deps(a) => deps(&a),
        DmCmd::Rename(a) => rename(&a),
        DmCmd::Message(a) => message(&a),
        DmCmd::Wait(a) => wait(&a),
        DmCmd::Targets => targets(),
    }
}

fn create(a: &Create) -> Result<()> {
    let rows = table_input::read_table(a.table.as_deref())?;
    let control = control::open()?;
    let device = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    if let Some(uuid) = &a.uuid {
        control.set_uuid(&a.name, uuid).context("set uuid")?;
    }
    let mut builder = device.builder();
    if a.readonly {
        builder = builder.read_only();
    }
    for row in &rows {
        builder = builder
            .add_raw(row.start, row.length, &row.target, &row.params)
            .with_context(|| format!("add {} target", row.target))?;
    }
    builder.load().context("load table")?;
    device.resume().context("resume")?;
    Ok(())
}

fn reload(a: &Reload) -> Result<()> {
    let device = control::by_name(&a.name)?;
    let rows = table_input::read_table(a.table.as_deref())?;
    let mut builder = device.builder();
    for row in &rows {
        builder = builder
            .add_raw(row.start, row.length, &row.target, &row.params)
            .with_context(|| format!("add {} target", row.target))?;
    }
    builder.load().context("load table")
}

fn table(a: &Name) -> Result<()> {
    for row in control::by_name(&a.name)?.table().context("read table")? {
        println!("{row}");
    }
    Ok(())
}

fn status(a: &Name) -> Result<()> {
    for row in control::by_name(&a.name)?.info().context("read status")? {
        println!("{row}");
    }
    Ok(())
}

fn info(a: &Name) -> Result<()> {
    let (device, status) = control::lookup(&a.name)?;
    let id = device.id();
    let state = if status.is_suspended() {
        "SUSPENDED"
    } else {
        "ACTIVE"
    };
    let mut tables = Vec::new();
    if status.has_active_table() {
        tables.push("LIVE");
    }
    if status.has_inactive_table() {
        tables.push("INACTIVE");
    }
    let tables = if tables.is_empty() {
        "None".to_string()
    } else {
        tables.join(" / ")
    };
    println!("Name:              {}", a.name);
    println!("State:             {state}");
    println!("Tables present:    {tables}");
    println!("Open count:        {}", status.open_count());
    println!("Event number:      {}", status.event_nr());
    println!("Major, minor:      {}, {}", id.major(), id.minor());
    println!("Number of targets: {}", status.target_count());
    Ok(())
}

fn ls() -> Result<()> {
    for (name, device) in control::open()?.list().context("list devices")? {
        let id = device.id();
        println!("{name}\t({}:{})", id.major(), id.minor());
    }
    Ok(())
}

fn deps(a: &Name) -> Result<()> {
    let deps = control::by_name(&a.name)?.deps().context("read deps")?;
    let list = deps
        .iter()
        .map(|d| format!("({}, {})", d.major(), d.minor()))
        .collect::<Vec<_>>()
        .join(" ");
    println!("{} dependencies\t: {list}", deps.len());
    Ok(())
}

fn rename(a: &Rename) -> Result<()> {
    let control = control::open()?;
    if a.setuuid {
        control.set_uuid(&a.name, &a.new_name).context("set uuid")?;
    } else {
        control.rename(&a.name, &a.new_name).context("rename")?;
    }
    Ok(())
}

fn message(a: &Message) -> Result<()> {
    let text = a.words.join(" ");
    let reply = control::by_name(&a.name)?
        .message(a.sector, &text)
        .context("send message")?;
    if let Some(reply) = reply {
        println!("{reply}");
    }
    Ok(())
}

fn wait(a: &Wait) -> Result<()> {
    let (device, status) = control::lookup(&a.name)?;
    // Default to the current counter, so we block until the next event.
    let event_nr = a.event_nr.unwrap_or_else(|| status.event_nr());
    device.wait_event(event_nr).context("wait")?;
    Ok(())
}

fn targets() -> Result<()> {
    for t in control::open()?
        .list_versions()
        .context("list target versions")?
    {
        let [major, minor, patch] = t.version;
        println!("{:<16} v{major}.{minor}.{patch}", t.name);
    }
    Ok(())
}
