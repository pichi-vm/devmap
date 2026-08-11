// SPDX-License-Identifier: Apache-2.0

//! The `dm` persona — `dmsetup`-equivalent operations over
//! [`devmap_linux`].

use anyhow::{Context as _, Result};
use devmap_linux::{Control, Device};

use crate::cli::{Create, DmCmd, Message, Name, Reload, Rename, Wait};
use crate::table_input;

pub(crate) fn run(cmd: DmCmd) -> Result<()> {
    let control = Control::open().context("open /dev/mapper/control")?;
    match cmd {
        DmCmd::Create(a) => create(&control, &a),
        DmCmd::Reload(a) => reload(&control, &a),
        DmCmd::Remove(a) => by_name(&control, &a.name)?.remove().context("remove"),
        DmCmd::Suspend(a) => by_name(&control, &a.name)?.suspend().context("suspend"),
        DmCmd::Resume(a) => by_name(&control, &a.name)?.resume().context("resume"),
        DmCmd::Clear(a) => by_name(&control, &a.name)?
            .clear_inactive_table()
            .context("clear"),
        DmCmd::Table(a) => table(&control, &a),
        DmCmd::Status(a) => status(&control, &a),
        DmCmd::Info(a) => info(&control, &a),
        DmCmd::Ls => ls(&control),
        DmCmd::Deps(a) => deps(&control, &a),
        DmCmd::Rename(a) => rename(&control, &a),
        DmCmd::Message(a) => message(&control, &a),
        DmCmd::Wait(a) => wait(&control, &a),
        DmCmd::Targets => targets(&control),
    }
}

fn by_name(control: &Control, name: &str) -> Result<Device> {
    Ok(control
        .by_name(name)
        .with_context(|| format!("look up {name}"))?
        .0)
}

fn create(control: &Control, a: &Create) -> Result<()> {
    let rows = table_input::read_table(a.table.as_deref())?;
    let removed = control
        .create(&a.name)
        .with_context(|| format!("create {}", a.name))?;
    if let Some(uuid) = &a.uuid {
        control.set_uuid(&a.name, uuid).context("set uuid")?;
    }
    let mut builder = removed.builder();
    if a.readonly {
        builder = builder.read_only();
    }
    for row in &rows {
        builder = builder
            .add_raw(row.start, row.length, &row.target, &row.params)
            .with_context(|| format!("add {} target", row.target))?;
    }
    builder.load().context("load table")?;
    removed.resume().context("resume")?;
    // Disarm the removal guard so the device outlives this process.
    let _ = Device::from(removed);
    Ok(())
}

fn reload(control: &Control, a: &Reload) -> Result<()> {
    let device = by_name(control, &a.name)?;
    let rows = table_input::read_table(a.table.as_deref())?;
    let mut builder = device.builder();
    for row in &rows {
        builder = builder
            .add_raw(row.start, row.length, &row.target, &row.params)
            .with_context(|| format!("add {} target", row.target))?;
    }
    builder.load().context("load table")
}

fn table(control: &Control, a: &Name) -> Result<()> {
    for row in by_name(control, &a.name)?.table().context("read table")? {
        println!("{row}");
    }
    Ok(())
}

fn status(control: &Control, a: &Name) -> Result<()> {
    for row in by_name(control, &a.name)?.info().context("read status")? {
        println!("{row}");
    }
    Ok(())
}

fn info(control: &Control, a: &Name) -> Result<()> {
    let (device, status) = control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?;
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

fn ls(control: &Control) -> Result<()> {
    for (name, device) in control.list().context("list devices")? {
        let id = device.id();
        println!("{name}\t({}:{})", id.major(), id.minor());
    }
    Ok(())
}

fn deps(control: &Control, a: &Name) -> Result<()> {
    let deps = by_name(control, &a.name)?.deps().context("read deps")?;
    let list = deps
        .iter()
        .map(|d| format!("({}, {})", d.major(), d.minor()))
        .collect::<Vec<_>>()
        .join(" ");
    println!("{} dependencies\t: {list}", deps.len());
    Ok(())
}

fn rename(control: &Control, a: &Rename) -> Result<()> {
    if a.setuuid {
        control.set_uuid(&a.name, &a.new_name).context("set uuid")?;
    } else {
        control.rename(&a.name, &a.new_name).context("rename")?;
    }
    Ok(())
}

fn message(control: &Control, a: &Message) -> Result<()> {
    let text = a.words.join(" ");
    let reply = by_name(control, &a.name)?
        .message(a.sector, &text)
        .context("send message")?;
    if let Some(reply) = reply {
        println!("{reply}");
    }
    Ok(())
}

fn wait(control: &Control, a: &Wait) -> Result<()> {
    let (device, status) = control
        .by_name(&a.name)
        .with_context(|| format!("look up {}", a.name))?;
    // Default to the current counter, so we block until the next event.
    let event_nr = a.event_nr.unwrap_or_else(|| status.event_nr());
    device.wait_event(event_nr).context("wait")?;
    Ok(())
}

fn targets(control: &Control) -> Result<()> {
    for t in control.list_versions().context("list target versions")? {
        let [major, minor, patch] = t.version;
        println!("{:<16} v{major}.{minor}.{patch}", t.name);
    }
    Ok(())
}
