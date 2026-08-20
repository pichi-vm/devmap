# devmap

A high-level, safe Rust interface to the Linux **device-mapper** control
ioctls. Create device-mapper devices, build and load their tables, read
tables and runtime status back, suspend/resume, and send target messages —
all through typed Rust rather than hand-packed `struct dm_ioctl` buffers.

Built on [`iocuddle`](https://crates.io/crates/iocuddle); the only `unsafe`
in the crate is the ioctl-number declarations, confined to one module.

## Requirements

- **Linux** (device-mapper is a Linux subsystem).
- **`CAP_SYS_ADMIN`** (typically root) to open `/dev/mapper/control`.

## Quick start

```rust
use devmap::{Control, targets::{Zero, Linear}, DevId};

fn main() -> Result<(), devmap::Error> {
    let control = Control::open()?;              // /dev/mapper/control
    let dev = control.create("my-device")?;

    // Build a table one target at a time, straight into one load buffer.
    dev.builder()
        .add(0,    8192, Zero)?                                  // 8192 sectors of zero
        .add(8192, 1024, Linear { device: DevId::new(252, 0), offset_sectors: 0 })?
        .load()?;                                               // DM_TABLE_LOAD
    dev.resume()?;                                              // activate the staged table

    let status = dev.status()?;
    println!("{} — {} target(s), open_count {}",
             dev.id(), status.target_count(), status.open_count());

    dev.remove()?;                              // teardown is always explicit

    Ok(())
}
```

## The model

- **`Control`** — the `/dev/mapper/control` fd; a factory for devices:
  `open`, `create`, `by_device`, `by_node`, `by_name`, `by_uuid`, `list`.
- **`Device`** — a plain handle identified by a **`DevId`** (`major:minor`).
  Everything else lives here: `builder`, `suspend`, `resume`, `remove`,
  `status`, `table`, `info`, `message`.
Dropping a `Device` does nothing to the kernel. A dm device is state that
outlives the process that made it, so this crate offers no `Drop`-based
autoremoval: a guard would fire on error paths and panics where the caller
wanted the device kept, would have nowhere to report a failed removal, and
would not run at all if the process were killed.

Teardown is therefore explicit, and there are two of them:

- **`Device::remove`** — remove now, and return the kernel's error if it
  can't (`EBUSY` for a device that is still open).
- **`Device::remove_deferred`** — `DM_DEFERRED_REMOVE`: remove now if
  unused, otherwise have the kernel remove it once the last holder closes
  it. This is the only autoremoval on offer, and it belongs to the kernel,
  which is the only thing that can still honour it after this process is
  gone.

## Building tables

`Device::builder()` streams targets into a single `DM_TABLE_LOAD` buffer;
`add` validates each target and `load` issues the ioctl. Targets are
structs in [`devmap::targets`]:

`zero`, `error`, `linear`, `striped`, `unstriped`, `dust`, `era`,
`log_writes`, `zoned`, `thin`, `verity`, `delay`, `flakey`, `writecache`,
`integrity`, `raid`, `thin_pool`, `snapshot` (`Snapshot`/`Origin`/`Merge`).

Targets with kernel-enforced constraints are built through validating
constructors (`Verity::new`, `Raid::new`, `ThinPool::builder()…build()`,
…) that reject values the kernel would refuse — so a bad table fails
early with `Error::Usage` instead of an opaque `EINVAL` at load time.

## Reading tables back

Two reads, distinguished by what the kernel returns:

```rust
// The mapping (STATUSTYPE_TABLE) — reconstruct the target you loaded:
for row in dev.table()? {
    if let Some(lin) = row.parse::<Linear>() {
        println!("{}..{} -> {}", row.start(), row.length(), lin.device);
    }
}

// Runtime status (STATUSTYPE_INFO) — per-target status. `parse::<T>()`
// returns T's runtime-status type (`RawInfo` unless a target models one):
for row in dev.info()? {
    if let Some(devmap::RawInfo(status)) = row.parse::<Linear>() {
        println!("{} linear: {status}", row.start());
    }
}
```

`Row::parse::<T>()` is name-checked and mode-safe: a `table()` row yields
the target, an `info()` row yields its `Target::Info` status type, and you
can't cross the two.

## Custom targets

The target set is open. Implement `Target` (plus `Display` to render its
params, and optionally `FromStr` to read it back) for any kernel target
this crate doesn't model:

```rust
use std::fmt;
use devmap::{Target, RawInfo};

struct MyTarget { /* … */ }
impl Target for MyTarget {
    const NAME: &'static str = "my-target";
    type Info = RawInfo;
}
impl fmt::Display for MyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "…kernel params…")
    }
}
// dev.builder().add(0, len, MyTarget { .. })?.load()?;
```

## Testing

Unit tests run anywhere; the integration tests under `tests/` need root
(they create real loop and dm devices and clean them up):

```sh
cargo test              # unit tests; integration tests skip without root
sudo -E cargo test      # full suite, exercising the real ioctls
```

## License

Apache-2.0.
