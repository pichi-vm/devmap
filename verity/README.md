# devmap-verity

`devmap-verity` reads dm-verity v1 superblocks and writes compatible hash
trees. Superblocks are validated before use, and tree data is streamed to a
seekable output.

The same types support synchronous `std::io` and asynchronous Tokio I/O.
Enable the `tokio` feature for asynchronous tree writing. Hash
implementations are selected with the optional `sha1`, `sha2`, `sha3`,
`ripemd`, `whirlpool`, `streebog`, `sm3`, and `blake2` features. `sha2` is
enabled by default.

See the [crate documentation](https://docs.rs/devmap-verity) for reading and
writing examples.

This crate creates superblocks and hash trees. It does not create or activate
Linux device-mapper devices.
