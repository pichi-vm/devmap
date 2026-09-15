# devmap

A device-mapper compatibility CLI backed by reusable Rust libraries.
Commands cover `dm`, `verity`, `crypt`, `integrity`, `snapshot`, `zoned`,
and thin/cache/era metadata. Legacy tool symlinks use the same command handlers.

- [`devmap-core`](core/): shared storage capabilities, adapters, and
  device-mapper interfaces.
- [`devmap-linux`](linux/): device handles, table submission, ioctls, and status.
- Target/format crates: target parameters, command codecs, and on-disk formats.
  [`devmap-verity`](verity/) and [`devmap-snapshot`](snapshot/) also provide
  userspace I/O; [`devmap-zero`](zero/) supplies a finite zero-filled source.

Every target definition lives in its owning crate's `dm` module, not in the
Linux backend. Applications depend on `devmap-linux` and the target crates they
use; both share the interfaces in `devmap-core`. The CLI handles compatibility
arguments and application workflows, such as sparse-file import, using those
libraries. See [MIGRATION.md](MIGRATION.md) for the target owners and composition
workflow, and [STYLE.md](STYLE.md) for repository conventions.

Verity header inspection and target construction work with
`default-features = false`, without any hashing libraries. Optional features
are named for the dependencies they enable; no separate activation feature is
required. See each crate's README for its feature list and API documentation.

Build with `cargo build --release -p devmap`.
Run portable checks with `cargo test --workspace --all-features --all-targets`.
Run `bash scripts/check-dependencies.sh` to check crate boundaries.

`bash scripts/test-kernel.sh` requires Linux device-mapper access and sudo/root.
It exercises the kernel using disposable loop/configfs devices and does not
unload shared modules. Reference-tool checks require cryptsetup/veritysetup,
thin-provisioning-tools, and dmzadm as applicable.

Licensed under Apache-2.0.
