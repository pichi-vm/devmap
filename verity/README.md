# devmap-verity

`devmap-verity` opens dm-verity hash devices for metadata inspection, formats
hash trees, and exposes authenticated data through standard or Tokio I/O.

Start with `Hashes::open` and `.header()` to inspect a hash device without
its data device or trusted root. With `default-features = false`, header
inspection and target descriptions depend only on `devmap-core` and its
dependencies, not on hashing implementations.

Build kernel parameters with `dm::Builder::from(hashes.header())`, supplying
the data and hash device IDs and an independently trusted root digest to
`build`. Pass the resulting `dm::Target` to a backend such as `devmap-linux`;
set the table read-only and use `target.data_sectors()` for a full-size row.
The `dm` module and its header conversions are available in every build.

Enable a hashing implementation to use `Formatter` and `Verity`.
Formatting returns a root digest to keep in trusted storage; `Verity`
authenticates data lazily when read. The crate does not activate Linux
device-mapper devices or manage trusted root storage.

SHA-2 support (`sha2`) is enabled by default. Optional `sha1`, `sha3`,
`ripemd`, `whirlpool`, `streebog`, `sm3`, and `blake2` features enable
those algorithms. The independent `tokio` feature adds asynchronous
operations, including metadata-only opening.

See the [API documentation](https://docs.rs/devmap-verity) for inspection,
formatting, authenticated-reading examples, and operational contracts.
