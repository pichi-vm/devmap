# devmap-linux

Generic Linux device-mapper control: create devices, construct and load tables,
suspend/resume them, query tables and status, and send target messages.

`Control` creates and finds `Device` handles. Build an inactive table with
`device.builder().add(start, length, target)?.load()?`, then activate it with
`device.resume()?`. Removal is explicit; dropping a handle does not remove
kernel state.

Target definitions live in separate crates, for example
`devmap_crypt::dm::CryptTarget` and `devmap_verity::dm::VerityTarget`.
Import shared target contracts, device numbers, and parsing/status helpers
directly from `devmap_core`.
Use `Device::message` to send raw target messages to a selected sector.

Use `device.table()` for construction parameters and `device.info()` for
per-target runtime status; `device.status()` reports whole-device state.
Typed rows preserve that distinction; raw parameters remain available for
unmodelled target types.

Real device operations require Linux and access to `/dev/mapper/control`
(normally root or CAP_SYS_ADMIN). Portable target codecs can be used separately.

There are no optional features. See the
[API documentation](https://docs.rs/devmap-linux) for complete workflows,
including verity header inspection followed by activation without hashing
dependencies.

Licensed under Apache-2.0.
