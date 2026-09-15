# devmap-core

`devmap-core` provides shared storage capabilities, I/O adapters, and
device-mapper interfaces. It defines no on-disk formats or concrete targets
and performs no device-mapper control ioctls.

Import storage operations from `traits::std`: `scale_to()` selects a logical
block size in bytes, `slice_bytes()` creates a zero-based view of an aligned
byte range, `byte_size()` reports the device extent, and `SyncData` provides
a persistence boundary. `scale()` and `slice()` work in multipliers and
logical blocks respectively.

The crate exports `Target`, `DevId`, `Fraction`, `NoInfo`, and
the `TableBuilder` trait used by target crates. Import these directly from
`devmap_core`. Concrete targets live in their owning crates; the Linux
backend implements these interfaces in `devmap-linux`. A finite zero-filled
source is available separately as `devmap_zero::Zero`.

Target crates parse their fields through `FromStr`; `Fraction<T>` handles the
shared `a/b` syntax used for counts and progress. It does not impose a
relationship between the two values.

There are no default features. Enable `tokio` and import `traits::tokio::*`
for the matching asynchronous storage interface.

See the [API documentation](https://docs.rs/devmap-core) for the supported
types and their contracts.
