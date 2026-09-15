# devmap

A device-mapper compatibility CLI backed by reusable Rust libraries.
The workspace focuses on seven libraries and a CLI with `dm`, `crypt`,
`verity`, and `snapshot` commands. The `dmsetup`, `cryptsetup`, and `veritysetup`
symlinks use the same command handlers.

- [`devmap-core`](core/): shared storage capabilities, adapters, and
  device-mapper interfaces.
- [`devmap-linux`](linux/): device handles, table submission, ioctls, and status.
- [`devmap-crypt`](crypt/): kernel crypt target parameters and status.
- [`devmap-luks`](luks/): LUKS headers, key handling, formatting, and crypt-target
  construction.
- [`devmap-snapshot`](snapshot/): snapshot metadata, userspace I/O, and targets.
- [`devmap-verity`](verity/): verity metadata, userspace verification, and targets.
- [`devmap-zero`](zero/): a finite zero-filled source and the kernel zero target.

Every target definition lives in its owning crate's `dm` module, not in the
Linux backend. Applications depend on `devmap-linux` and the target crates they
use; both share the interfaces in `devmap-core`. The CLI handles compatibility
arguments and application workflows, such as sparse-file import, using those
libraries. See [MIGRATION.md](MIGRATION.md) for the target owners and composition
workflow, and [STYLE.md](STYLE.md) for repository conventions.

The generic `dm` commands accept raw table parameters and messages for any
kernel-supported target. Dedicated format APIs and compatibility commands for
other targets are outside the current scope.

Verity header inspection and target construction work with
`default-features = false`, without any hashing libraries. Optional features
are named for the dependencies they enable; no separate activation feature is
required. See each crate's README for its feature list and API documentation.

Build with `cargo build --release -p devmap`.
Run portable checks with `cargo test --workspace --all-features --all-targets`.
Run `bash scripts/check-dependencies.sh` to check crate boundaries.

`bash scripts/test-kernel.sh` requires Linux device-mapper access and sudo/root.
It exercises the kernel using disposable loop devices and does not
unload shared modules. Reference-tool checks require cryptsetup/veritysetup.

Licensed under Apache-2.0.
