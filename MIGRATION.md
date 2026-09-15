# Crate ownership and composition

## Model

Applications combine a backend with the target crates they need. A target
describes its parameters; a table row adds a start and length in 512-byte
sectors, and the table has one access mode. Creating a device, loading its
inactive table, resuming it, and removing it are separate backend operations.

- `devmap-core`: `Target` and shared field types in `parse`.
- `devmap-linux`: device handles, ioctl encoding, tables, status, and messages.
- Target/format crates: target definitions and parameter/status codecs.

## Target owners

| Kernel target | Owner | Type |
| --- | --- | --- |
| crypt | devmap-crypt | `dm::CryptTarget` |
| snapshot | devmap-snapshot | `dm::SnapshotTarget` |
| snapshot-origin | devmap-snapshot | `dm::SnapshotOriginTarget` |
| snapshot-merge | devmap-snapshot | `dm::SnapshotMergeTarget` |
| verity | devmap-verity | `dm::VerityTarget` |
| zero | devmap-zero | `ZeroTarget` |

Concrete targets implement `devmap_core::Target`.
Send raw target messages with Linux's `Device::message`.
Read typed runtime status with
`device.target::<T>(sector).info()`.
Import the `Target` trait from `devmap_core`; `DevId`, `Fraction`, `Empty`,
and `Error` live in `devmap_core::parse`. Linux exposes its own backend
handles, builders, and rows.
`devmap_zero::Zero` supplies the userspace zero-filled source;
`devmap_zero::ZeroTarget` describes the kernel target. The userspace source
supports reads and seeks; the kernel target also accepts and discards writes.

`Target::Info` can be `String` when arbitrary status text should be preserved.
Use core's `Empty` only when empty or whitespace-only status is required.

Normal dependencies flow to core, not between Linux and target crates.
LUKS is separate from raw crypt, with optional header-to-crypt conversion.

## Dependencies and features

- Core is a normal dependency of all six other libraries. Crypt, snapshot,
  verity, and zero always provide target definitions. Verity's no-default-feature
  build supports header inspection and target construction without hashing libraries.
- LUKS's optional `devmap-crypt` dependency enables header-to-target conversion.
  All opt-in Cargo features are named for the optional dependencies they enable.
- Hashing implementations are optional dependencies of verity; enabling one
  exposes its formatting and authenticated-reading APIs. Algorithm metadata
  remains available regardless of which implementations are enabled.
- Core, snapshot, verity, and zero offer Tokio storage operations through the
  optional `tokio` dependency. Target descriptions do not require it.

## Header to activation

For an existing verity hash device:

1. Open its hash storage with `Hashes::open`, importing `OpenHashes` from
   `devmap_verity::traits::std` or `traits::tokio`. No data device or root is
   required for this step.
2. Call `hashes.parameters().target(data_id, hash_id, trusted_root)`.
   The header does not contain that root.
3. For an embedded header, open through a zero-based region and set the
   target's `with_header_offset_bytes` to its offset in the Linux hash device.
4. Create a Linux device. On `device.builder()`, call `read_only()` and
   `add(0, target.data_sectors(), target)` for a full-size row. `load()` stages
   the table and `device.resume()` activates it.

The ordinary table builder also accepts an explicitly selected shorter row.
Header validation is not data authentication. Persist newly formatted hash
storage with `SyncData` before kernel activation. Device removal is explicit,
including cleanup after a failed load or resume. The
[Linux API documentation](https://docs.rs/devmap-linux) has a compiling example.

## Storage and formatting

- Core's `scale_to(bytes)` selects a final logical-block size,
  `slice_bytes(range)` selects an aligned byte range, and `byte_size()` reports
  the complete extent. Scaling does not resize storage.
- Verity's `Parameters::builder()` configures both formatting and targets.
  The format traits take `format(data, hashes, uuid)` and return `(Hashes, root)`.
  Stored metadata is available through `Hashes::uuid()` and `parameters()`.
- Snapshot's `Layer::create` initializes metadata in preallocated COW storage.
  Before allocating a new chunk, a write matching the origin succeeds without
  promotion. Raw-image import and sparse-file traversal belong in application
  code. For a newly created layer above `devmap_zero::Zero`, skipped holes and
  written zero blocks need no allocation.
- LUKS's `Header::open` reads metadata; its payload and target-conversion
  methods provide the offsets, extents, and cipher parameters for activation.

## Verification commands

```sh
bash scripts/check-dependencies.sh
cargo fmt --all --check
cargo test --workspace --all-features --all-targets
cargo test --workspace --no-default-features --all-targets
cargo test --workspace --all-features --doc
cargo clippy --workspace --all-features --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
package_check_dir=$(mktemp -d)
cargo package --workspace --allow-dirty --all-features --target-dir "$package_check_dir"
bash scripts/test-kernel.sh
```

Package verification uses a fresh target directory to avoid stale cached
workspace packages with the same unpublished version.

The kernel runner uses private loop devices and never unloads shared
modules. It requires root or passwordless sudo and refuses to run without an
accessible device-mapper control node. An optional first argument selects test
binary names by regex. Runtime skip messages still indicate missing coverage.

CI also builds target crates independently and checks minimal header/target,
Tokio-only, and individual hashing features. Crates that declare Rust 1.85
are checked on that compiler.
