# devmap-verity

Inspect dm-verity metadata, build hash trees, and read authenticated data.
Start with `Hashes` for metadata, `Parameters::builder()` to configure formatting or a target, or
`Verity` to verify reads against a trusted root. Kernel activation belongs
to `devmap-linux`.

Disable default features for metadata and target descriptions without hashing
dependencies. `sha2` is the default; `sha1`, `sha3`, `ripemd`, `whirlpool`,
`streebog`, `sm3`, and `blake2` enable other families. `tokio` adds asynchronous
operations independently of hashing.

See the [API documentation](https://docs.rs/devmap-verity) for examples and
the individual contracts.
