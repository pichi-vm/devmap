# devmap-integrity

Device-mapper `integrity` target parameters, status, header inspection, and
kernel-assisted formatting. Start with `dm::Target`; use a backend such as
`devmap-linux` to load it in a table. `Header::open` reads the capacity recorded
in an existing superblock without loading a target.

`dm::Target::format` initializes backing storage through a temporary kernel
mapping using the backend interfaces in `devmap-core`. Formatting is
destructive and requires exclusive access to the backing device. The crate
does not implement device-mapper ioctls or userspace integrity-tag I/O.

There are no optional features. See the [API documentation](https://docs.rs/devmap-integrity).
