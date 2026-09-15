# devmap-core

`devmap-core` provides shared storage capabilities, I/O adapters, and
device-mapper interfaces. It defines no on-disk formats or concrete targets
and performs no device-mapper control ioctls.

Import storage operations from `traits::std`: `scale_to()` selects a logical
block size in bytes, `slice_bytes()` creates a zero-based view of an aligned
byte range, `byte_size()` reports the device extent, and `SyncData` provides
a persistence boundary. `scale()` and `slice()` work in multipliers and
logical blocks respectively.

The crate exports `Target`, `Region`, and `Scaled` at its root. The `parse`
module supplies `DevId`, `Fraction`, `NoInfo`, and `Error` for target parameters
and status. Concrete targets implement `Target` in their owning crates;
`devmap-linux` uses these descriptions to load tables and parse replies.
A finite zero-filled source is available separately as `devmap_zero::Zero`.

Target crates parse their fields through `FromStr`; `Fraction<T>` handles the
shared `a/b` syntax used for counts and progress. It does not impose a
relationship between the two values.

There are no default features. Enable `tokio` and import `traits::tokio::*`
for the matching asynchronous storage interface.

See the [API documentation](https://docs.rs/devmap-core) for the supported
types and their contracts.
