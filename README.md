# devmap

Small Rust libraries for the device-mapper facilities shared by pichi
components. The workspace contains three libraries and no applications:

- [`devmap-core`](core/) contains shared block-size and storage-geometry types.
- [`devmap-linux`](linux/) controls Linux device-mapper, owns the `Target`
  contract and target grammar values, and provides targets that have no shared
  on-disk format: crypt, snapshot, snapshot-origin, snapshot-merge, and zero.
- [`devmap-verity`](verity/) owns the standard verity header, streaming hash
  formatter, and verity target.

Verity header inspection works on every platform. Its target API is available
on Linux. No hash family is enabled by default; hash features enable formatting. Synchronous code
imports `devmap_verity::Format`; Tokio code imports
`devmap_verity::AsyncFormat`.

```sh
cargo test --workspace --all-features --all-targets
```

The GitHub Actions workspace workflow also runs feature-isolation, packaging,
documentation, and real-kernel tests. Kernel tests need device-mapper access
and root privileges; the workflow provisions disposable loop devices for them.

Licensed under Apache-2.0.
