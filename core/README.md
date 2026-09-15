# devmap-core

Shared storage adapters and device-mapper target descriptions for the devmap
format crates. This crate does not implement on-disk formats or activate devices.

Start with `traits::std` for storage operations or `Target` for kernel target
descriptions. See the [API documentation](https://docs.rs/devmap-core) for a
working example and the individual API contracts.

No default features. `tokio` enables the matching asynchronous interfaces.
