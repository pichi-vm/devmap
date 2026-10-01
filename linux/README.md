# devmap-linux

`devmap-linux` creates and manages Linux device-mapper devices. A
device-mapper device presents a virtual block device backed by one or more
*targets*. This crate owns the control operations and targets that have no
shared on-disk format. A target with a shared format, such as dm-verity, lives
in its format crate.

Creating a mapping has three steps: create the device, load a table describing
its targets, then resume the device to make the table active. The steps are
separate kernel operations, not a transaction. A failed load or resume can
leave the created device behind.

When adding a target, the table builder asks the kernel for that target's
version and caches it for other rows of the same type. The target uses the
version to encode its parameters or reject an unsupported version. Separately,
`Control::versions()` enumerates targets already registered with the
kernel; a loadable module may be absent from that list until requested by
name. Target versions are distinct from the device-mapper ioctl version.
Version checks cover known syntax changes; the kernel still validates the
complete table against its configuration and backing devices.

Reading a table or runtime status also resolves each distinct target version
before returning rows. A row carries that version, so its mode-specific
parser can interpret the kernel's text without performing further I/O. A
version lookup failure makes the read fail.

## Create a temporary zero device

The `zero` target returns zeroes for every read. This example creates a
4 MiB mapping, opens it, and asks the kernel to remove it once the last open
file is closed. It needs Linux device-mapper access, normally `CAP_SYS_ADMIN`.

```rust,no_run
use std::{fs::OpenOptions, io::Read as _};
use devmap_linux::{Control, target::zero::ZeroTarget};

# fn main() -> std::io::Result<()> {
let control = Control::open()?;
let device = control.create("my-zero")?.guard();

// Table lengths are in 512-byte sectors: 8192 sectors = 4 MiB.
device.builder().add(0, 8192, ZeroTarget)?.load()?;
device.resume()?;

let mut file = device.defer(OpenOptions::new().read(true))?;
let mut sector = [1; 512];
file.read_exact(&mut sector)?;
assert_eq!(sector, [0; 512]);
# Ok(())
# }
```

The guard attempts immediate removal if the example fails after device
creation. That cleanup only runs when Rust unwinds; it cannot handle a process
crash. Calling `defer` opens the mapping and switches to kernel-managed
deferred removal. The mapping remains until *all* open holders close, even if
the creating process exits. A plain device handle has a different lifetime:
dropping it leaves the kernel device in place.

## Inspect an existing mapping

A table reports the parameters used to construct a target. Target info reports
its current runtime state. Whole-device status answers a different question:
whether the mapping exists and is active. The kernel can normalize table
parameters, so read-back text need not match what was originally loaded.

Targets can be rendered and parsed without opening the device-mapper control
device. Creating, changing, or inspecting live mappings requires access to
`/dev/mapper/control`.
