# devmap-zero

A finite, seekable source of zero bytes and a Linux device-mapper target
description. `Zero::new(length)` provides standard reads, seeks, and core
geometry without allocating backing storage. The `dm::Target` type describes
the kernel zero target, which also accepts and discards writes; use a backend
such as `devmap-linux` to activate it.

There are no default features. Enable `tokio` for asynchronous reads, seeks,
and geometry on `Zero`. The crate does not manage devices or issue ioctls.

See the [API documentation](https://docs.rs/devmap-zero).
