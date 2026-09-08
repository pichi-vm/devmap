# devmap-snapshot

`devmap-snapshot` reads, writes, and merges the dm-snapshot persistent
copy-on-write store, byte-exact per `drivers/md/dm-snap-persistent.c`.

A `Layer` is a seekable byte stream over an origin device. Reads are routed
through its exception map and writes allocate full COW chunks. A layer uses
standard byte-stream traits, so layers nest without project-specific block
interfaces.

`convert` and `convert_sparse` write a raw image into a new store over a zero
origin, choosing the layer for a chunk size known at run time.

The same types support synchronous `std::io` and asynchronous Tokio traits.
Enable the `tokio` feature for asynchronous I/O. `SyncData` and
`AsyncSyncData` provide the persistence barrier that `flush` does not.

See the [crate documentation](https://docs.rs/devmap-snapshot) for reading and
writing examples.

This crate reads and writes the on-disk format. It does not create or activate
Linux device-mapper devices.
