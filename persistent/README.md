# devmap-persistent

Read, check, and restore the persistent-data metadata shared by dm-thin,
dm-cache, and dm-era. The crate provides block validation, btrees, arrays,
space maps, and the corresponding dump/restore formats.

It does not activate device-mapper devices. Kernel target descriptions live
in their target crates and kernel operations live in `devmap-linux`.
There are no optional features.

See the [API documentation](https://docs.rs/devmap-persistent).
Licensed under Apache-2.0.
