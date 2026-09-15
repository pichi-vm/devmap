# devmap-zoned

Compute and write dm-zoned metadata and read its superblock. The layout
calculation is portable; querying physical zone geometry and formatting a
device path are available on Linux. Start with `Layout::compute` to calculate
metadata or `Superblock::open` to inspect an existing primary superblock.

The `dm` module always provides the kernel target description, typed status,
and reclaim command extension. Pass the target to a device-mapper backend to
activate it. This crate does not implement device-mapper control ioctls.

There are no optional features. See the
[API documentation](https://docs.rs/devmap-zoned).
Licensed under Apache-2.0.
