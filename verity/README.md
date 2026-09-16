# devmap-verity

Inspect verity hash volumes, format and persist hash trees, and read verified
data. `Scheme` selects hashing, `Shape` describes geometry, and `Options`
constructs a userspace reader or a `VerityTarget`. Linux activation belongs
to `devmap-linux`.

Salt is inline, limited to 256 bytes. Disable default features for metadata
and target descriptions without hashing implementations. `sha2` is the default;
`sha1`, `sha3`, `ripemd`, `whirlpool`, `streebog`, `sm3`, and `blake2`
enable other families. `tokio` adds asynchronous operations independently.

See the [API documentation](https://docs.rs/devmap-verity) for workflows and
operation contracts.
