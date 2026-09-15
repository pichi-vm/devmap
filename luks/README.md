# devmap-luks

Read, format, and unlock LUKS1 and LUKS2 volumes. `Header::open` reads the
format's header copies, and `Header::unlock` recovers a zeroizing master key.
The crate does not activate device-mapper devices.

The optional `devmap-crypt` feature converts header settings and a supplied key
reference into a `devmap-crypt` target. Plain dm-crypt users should depend
on that target crate directly; they do not need the LUKS implementation.

See the [API documentation](https://docs.rs/devmap-luks).
Licensed under Apache-2.0.
