# devmap-crypt

Device-mapper `crypt` target parameters and status. Start with `dm::CryptTarget`;
use a device-mapper backend such as `devmap-linux` to load it in a table.
This crate does not manage devices or issue device-mapper ioctls.

There are no optional features. See the [API documentation](https://docs.rs/devmap-crypt).
