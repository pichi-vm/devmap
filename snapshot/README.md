# devmap-snapshot

`devmap-snapshot` provides a seekable copy-on-write layer backed by the Linux
dm-snapshot persistent COW format.

Import `traits::std::*` for standard I/O or `traits::tokio::*` for Tokio I/O.
The operation names are identical; asynchronous calls additionally require
`.await`.

The caller chooses and sizes both the origin and COW storage.
`Layer::create` initializes metadata in a preallocated COW; it does not copy
origin data or discover sparse-file holes. `Formatter::required_size` computes
capacity for a change to every origin chunk. Before allocating a new COW
chunk, writes are compared with the origin; matching bytes need no allocation.
File import and sparse-file traversal belong to the caller.

The `dm` module always provides `SnapshotTarget`, `SnapshotOriginTarget`, and
`SnapshotMergeTarget`. Pass them to a backend such as `devmap-linux` for
activation; this crate does not create or activate device-mapper devices.

There are no default features. Enable `tokio` for the `traits::tokio` module
and Tokio I/O implementations on `Layer`.

See the [API documentation](https://docs.rs/devmap-snapshot) for a complete
example and the storage, flushing, and durability contracts.
