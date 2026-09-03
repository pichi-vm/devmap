# API review findings

This file records the multi-agent API review of `linux/` and `verity/`.
Items are ordered roughly by correctness risk and then by API impact. Work
through them independently; do not treat the ordering as a requirement to
combine unrelated changes.

## Direction

- [ ] Preserve `devmap-verity` as a fully featured dm-verity format library.
  Do **not** solve validation or cross-crate inconsistencies by locking it to a
  single v1/SHA-256/4 KiB profile.
- [ ] Preserve the boundary between the crates: `verity/` owns portable
  on-disk formats and hash-tree computation; `linux/` owns Linux ioctls and
  live device-mapper state. Keep composition in callers rather than adding a
  `devmap-linux` dependency to `devmap-verity`.
- [ ] Keep all workspace crates compiling while these APIs evolve. Use
  `cargo check --workspace --all-targets` as the compatibility gate.

## Structure

- [x] Split `verity/src/lib.rs` into private `tree` and `superblock` modules,
  with one public type per focused source file where practical.
- [x] Split the former inline test module by contract: public API coverage is
  under `verity/tests/`, `veritysetup` compatibility has its own integration
  test target, and private tree-helper tests live under `verity/src/tree/`.
- [x] Remove the temporary test-only crate-root re-exports; private helpers are
  now visible only to their owning module's unit tests.
- [x] Keep `Superblock` as the only type in `superblock/mod.rs`; move each wire
  field type into its own file and replace redundant format constants with
  enum variants and capacities derived from their wire fields.

## Verity: correctness and format coverage

### Validate the complete parameter space

- [x] Reject block sizes that are not cryptsetup-compatible powers of two in
  the inclusive 512-byte through 512-KiB range.
- [x] Validate the complete currently supported parameter space: format
  version, hash type, algorithm, block sizes, salt limit, tree layout, and
  arithmetic overflow.
- [ ] Add boundary tests for every accepted block size and digest size, plus
  rejection tests for each invalid boundary. Cross-check representative valid
  combinations against `veritysetup format` and `veritysetup verify`.
- [x] Make layout computations checked and explicit. No accepted parameter set
  should be able to truncate the superblock, overflow a size calculation, or
  build a tree the Linux target cannot describe.

### Generalize the hashing model

- [x] Remove SHA-256 assumptions from the tree algorithm. Introduce an
  algorithm abstraction that supplies the algorithm name, digest size, and a
  hashing operation/factory.
- [ ] Support the salt ordering required by each dm-verity format version
  instead of baking v1's `HASH(salt || block)` into the only implementation.
- [ ] Keep raw root hashes and salts as bytes at the library boundary; hex is a
  CLI/table codec concern.
- [x] Decide which algorithms are implemented in-tree and how additional
  algorithms can be added without making the core API depend on Linux's crypto
  API at runtime.

### Decode into valid domain values

- [x] Make `Superblock::read` return only a fully validated, supported
  `Superblock`. It rejects invalid signatures, versions, hash types,
  algorithms, salts, block sizes, padding, and overflowing layouts.
- [x] Make `verity open` and `verity verify` consume this validated type rather
  than performing a second round of format validation.
- [ ] If inspection of unsupported future records becomes a concrete need,
  add a separate raw record type. Never allow that type to construct a
  `TreeWriter` without conversion into a validated `Superblock`.
- [ ] Consider richer decoding errors so callers can distinguish unsupported
  but well-formed values from malformed bytes. The current API intentionally
  reports both as `io::ErrorKind::InvalidData`.

### Make format offsets compose end to end

- [x] Make the stream position explicit: `Superblock::write` emits the header
  block at the current position, and `Superblock::tree_writer` starts the tree
  at the writer's current position.
- [ ] Ensure every layout that `verity format` can create can also be consumed
  by `verity open` and represented by `linux::targets::Verity`.
- [ ] Generalize `linux::targets::Verity`; it currently hard-codes format
  version 1, 4096-byte data/hash blocks, and hash start block 1.
- [ ] Extend the Linux target model to cover dm-verity optional arguments,
  including corruption policy, ignored zero blocks, FEC, and root-hash
  signatures, without silently dropping unmodelled table fields.

## Verity: validated superblock and streaming writer

- [x] Replace the borrowed zerocopy wire view with an owned domain
  `Superblock` whose private fields can represent only supported values.
- [x] Validate every field during `Builder::build` or `Superblock::read`.
  Oversized salts and unsupported `Algorithm` values fail with `io::Error`
  before they can reach a superblock.
- [x] Add explicit `Superblock::read` and `Superblock::write` codecs. Both
  include the padding up to the hash-block boundary, leaving the stream at the
  tree start.
- [x] Compose the superblock incrementally through private `Decode` and
  `Encode` traits while retaining inherent `Superblock::read` and `write` as
  the only public codec API.
- [x] Remove the public `BlockSize` wrapper. Both fallible builder setters take
  `u32` byte counts and enforce cryptsetup's shared bounds immediately; the
  validated superblock exposes those byte counts directly.
- [x] Replace `TreeBuilder` with `TreeWriter`, constructed only through
  `Superblock::tree_writer`. It owns the validated configuration and performs
  no duplicate format validation.
- [x] Keep tree output streaming and bounded to one data block plus one hash
  block per level; retain `Write + Seek` because upper levels precede leaves.
- [x] Store validated tree geometry with the superblock so slot width, level
  counts, and tree length have one source of truth. Keep hash-level buffers
  fixed-size and their progress state private.
- [x] Preserve `Write` error semantics by emitting a completed data block
  before accepting bytes from the next call and poisoning the adapter after a
  downstream failure.
- [x] Return both the owned output and the typed `Digest` from
  `TreeWriter::finish`, preserving the selected algorithm and digest length at
  the public boundary.
- [x] Migrate the root CLI and byte-for-byte `veritysetup` integration tests to
  the validated API.
- [x] Generalize `Algorithm` beyond SHA-256 without weakening the invariant
  that every constructed algorithm has a hashing implementation.

## Superseded design record: zerocopy wire model

The following completed items record the earlier design exploration. They are
not current requirements: the valid-by-construction domain model above
intentionally supersedes the public zerocopy record, truncating `Salt`, and
independently validated `TreeBuilder` APIs.

- [x] Make the public `Superblock` itself the `#[repr(C)]` 512-byte wire
  record, with private fields and native-value accessors. Bind borrowed bytes
  with `zerocopy::TryFromBytes`; do not maintain a separate parsed model or a
  hand-written fixed-offset decoder.
- [x] Use explicit little-endian integer fields, for example
  `zerocopy::byteorder::little_endian::{U16, U32, U64}`. Do not use native-endian
  integers for this on-disk format.
- [x] Derive the appropriate `zerocopy` traits and add compile-time assertions
  for the exact 512-byte size and field layout.
- [x] Express closed wire fields through zerocopy validity: an exact signature
  enum plus endian-aware `SuperblockVersion` and `HashType` enums wrapped in
  `Unalign`. Keep opaque UUID/reserved fields as byte arrays,
  predicate-constrained sizes and counts as endian integers, and dependent
  algorithm/salt fields in focused wrappers.
- [x] Keep bit-validity separate from dependent-field interpretation. Zerocopy
  rejects an unknown signature, version, or hash type while the `Algorithm`
  and salt accessors interpret their own fields without a redundant whole-record
  validation pass or a second representation.
- [x] Preserve byte-for-byte compatibility tests against `veritysetup` while
  changing the codec.

The likely historical reason for the current manual codec is that this crate
was moved from an already proven implementation and kept its explicit byte
assembly. That is not a reason to retain duplicate offsets now that the
workspace already uses `zerocopy` for fixed binary layouts in `linux/`.

### Exhaustive type and method audit

This audit covers every type, method, associated constant, free function, and
intentional trait implementation currently declared under `verity/src`. A use
in a test is not, by itself, a reason to keep public API; the dispositions below
also account for the intended fully featured format-library role.

#### Remove or simplify now

- [x] Finish the manual `Algorithm::name` change coherently. It now returns
  `Utf8Error` directly, so remove the dead `SuperblockError::BadAlgorithm`
  variant and update the stale method documentation and integration test.
- [x] Remove `HashType::as_u32` and `SuperblockVersion::as_u32`. Each exists
  only for its `Display` implementation and one test assertion. Keep the
  endian conversion private inside `Display`; callers should use the semantic
  enum variants.
- [x] Remove `Superblock::salt_field` and the internal `Salt::field`. They are
  used only by one test and expose padding rather than the meaningful salt;
  whole-record bytes remain available through zerocopy's `IntoBytes`.
- [x] Remove `derive_uuid` from the library. It is test-only
  cosmetic policy, while the production formatter generates a random UUID.
  Use explicit fixed UUIDs in deterministic fixtures.
- [x] Replace the accumulating tree builder with a `Write` implementation that
  retains one data block and one hash block per level.
- [x] Remove the test-only `compute_levels` implementation and its unit test.
  Production computes levels by walking them, so testing a second unused
  formula cannot detect regressions in the real implementation.
- [x] Correct the tree builder documentation to describe bounded streaming to
  a seekable hash-device output.

#### Keep as domain API

- [x] Replace `VerityParams` with `Builder`. Keep the legitimate
  superblock construction API, and reject invalid block sizes in their
  setters so every builder value is valid and construction remains infallible.
- [x] Accept block sizes directly in fallible builder setters, rejecting zero,
  non-power-of-two values, and hash blocks too small to collapse the tree.
- [x] Make `hash_type` and `algorithm` explicit superblock builder settings.
  The record builder preserves any `Algorithm`; implementation-specific
  algorithm support is checked only when constructing a `TreeBuilder`.
- [x] Store builder salt data directly in a fixed-capacity byte array rather
  than allocating a `Vec<u8>`. The builder accepts a slice and rejects input
  larger than the wire field.
- [x] Use `io::ErrorKind::InvalidInput` for both block-size setters. Callers
  only need to know whether the supplied size satisfies the shared invariant;
  malformed wire values are translated to `InvalidData` during conversion.
- [x] Replace the block-at-a-time protocol with `TreeBuilder: Write`. It accepts
  arbitrary input chunks and reports I/O failures through `io::Error`.
- [x] Remove `VerityOutput`; callers supply the hash-device writer and
  `TreeBuilder::finish` returns only the root hash.
- [x] Keep `Superblock` as the public wire value and keep
  `version`, `hash_type`, `uuid`, `algorithm`, `data_block_size`,
  `hash_block_size`, `data_blocks`, and `salt`. They are the semantic record
  fields required for inspection, activation, or computation.
- [x] Return the public `Salt` wire type from `Superblock::salt`. Its `len`
  and `AsRef<[u8]>` implementation interpret oversized recorded lengths as the
  field capacity.
- [x] Keep `Algorithm`, `Algorithm::SHA256`, and `Algorithm::name`. The open
  fixed-width newtype preserves unknown algorithm names for a fully featured
  library while keeping UTF-8 interpretation explicitly fallible.
- [x] Keep `HashType::{ChromeOs, Normal}` as a public typed enum. Keep the sole
  supported superblock version as a private codec detail until callers have a
  meaningful version choice to make.
- [x] Keep `Display` for `HashType` and `SuperblockVersion`: numeric formatting
  is useful at the cryptsetup boundary even though version formatting has no
  production workspace caller yet.
- [x] Treat oversized salt lengths as a noncanonical but valid encoding,
  silently truncating their semantic value to the fixed wire capacity.

#### Keep as wire implementation

- [x] Keep `Signature::Verity` and the public `Salt` value with `CAPACITY`,
  `new`, `len`, `is_empty`, `AsRef<[u8]>`, and truncating `append`; keep their wire
  fields private and retain all size, alignment, and offset assertions.
- [x] Keep superblock construction in `Builder::build`. Callers that want a
  complete hash-device image write that value and its padding before starting
  the independent tree builder.
- [x] Remove the free `hashes_per_block` and `hash_v1` functions. Level sizing
  and hashing are implementation details of `TreeBuilder`.
- [x] Keep zerocopy's `TryFromBytes`, `FromBytes`, `IntoBytes`, `KnownLayout`,
  `Immutable`, and `Unaligned` implementations where required by the wire
  graph. They are what lets `Superblock` remain the representation itself
  without restoring hand-written parsing or a second parsed model.
- [x] Keep ordinary value semantics (`Clone`, `PartialEq`, `Eq`, and `Hash`) on
  the small field types. Keep bytewise equality and hashing for `Superblock`
  only with an explicit contract that reserved bytes and padding participate.
- [ ] Reconsider `Superblock: Copy`. It currently lets the CLI own a value
  borrowed from its read buffer, but it also permits implicit 512-byte copies;
  `Clone` plus an inherent owned-read helper may make that cost explicit.
- [x] Do not expose `Debug` for `TreeBuilder`; its writer and in-flight buffers
  are implementation state rather than useful diagnostics.
- [x] Keep the error types' `Display` and `Error` implementations. Callers such
  as the root CLI rely on them through error-source chaining even when they
  erase the concrete type with `anyhow`.

#### Behavioral API issues exposed by the audit

- [x] Make empty input unambiguous: a declared count of zero produces no tree
  levels, while a nonzero count requires data for its final block.
- [x] Remove the separate reader helper and duplicated block-size argument.
  `io::copy` streams directly into `TreeBuilder` through its `Write` impl.
- [ ] Document whether `Algorithm == Algorithm::SHA256` intentionally requires
  canonical zero padding. It is stricter than `algorithm.name() == "sha256"`
  because equality compares all 32 wire bytes.
- [ ] Decide whether inspection must preserve unknown future numeric versions
  and hash types. Closed `TryFromBytes` enums intentionally reject them during
  binding; if a dump tool must distinguish “well-formed but unsupported” from
  malformed input, raw endian newtypes plus a later semantic conversion would
  be required. Do not weaken the enum representation without that concrete
  requirement.
- [ ] Keep the direct zerocopy binding path as the low-level decoder. Do not add
  an inherent parser that rebuilds the old duplicate representation merely to
  hide the zerocopy trait import; add a thin inherent facade only if it can
  return the same borrowed wire value without duplicating validation.
- [x] Require the authoritative data-block count when constructing
  `TreeBuilder`; this determines every level offset before input is streamed.

## Verity: public construction API

### Stream tree output

- [x] Implement `Write` for `TreeBuilder`, deriving its buffering from an
  owned `Superblock` configuration value rather than duplicating its fields.
- [x] Require `Write + Seek` for the hash-device output. The dm-verity layout
  places upper levels before leaves, so a one-pass builder must seek to each
  precomputed level offset.
- [x] Buffer arbitrary caller chunks into data blocks internally.
- [x] Propagate output failures directly as `io::Error`.

### Separate tree construction from superblock I/O

- [x] Let `TreeBuilder` own a `Superblock` as its configuration value so data
  counts, block sizes, hash type, algorithm, and salt have one representation.
  UUID and other record-only fields remain inert during hashing.
- [x] Keep superblock I/O outside `TreeBuilder`. It emits only tree blocks;
  callers that need a complete hash-device image write and pad the superblock
  separately.
- [ ] Keep a convenient one-shot formatting API returning both the serialized
  hash-device data and root hash.
- [x] Make verification stream into a seekable discard writer so it retains no
  serialized tree image.

## Linux: error boundaries and semantics

### Preserve typed row parse errors

- [ ] Add a fallible typed decoder for rows:

  ```rust
  row.decode::<T>() -> Result<Option<T::Table>, ParseError>
  row.decode::<T>() -> Result<Option<T::Info>, ParseError>
  ```

  A target-name mismatch should be `Ok(None)`; malformed parameters for the
  matching target should be `Err`.
- [ ] Make `LiveTarget::info` preserve the same distinction. It currently
  reports malformed matching status as if the requested target were absent.
- [ ] Keep `Row::params` as the raw, forward-compatible escape hatch.

### Clarify device identity APIs

- [ ] Make `Control::by_node` delegate to `DevId::from_path` immediately so it
  rejects regular files instead of wrapping their meaningless `st_rdev` as
  device `0:0`.
- [ ] Decide whether `Control::by_node` should remain public. Backing-device
  paths generally need a `DevId`, not a device-mapper `Device`; callers can use
  `DevId::from_path` and `Control::by_device` explicitly.
- [ ] Keep `/dev/dm-<minor>` path construction on `Device`, where the identity
  is known to be a device-mapper mapping. Reconsider `DevId::node_path`, since
  a `DevId` can also identify a loop disk or any other block device.

### Make removal retryable

- [ ] Change `Device::remove` and `Device::remove_deferred` to borrow `&self`.
  Consuming one clone does not invalidate other handles, and losing the handle
  after `EBUSY` prevents a natural retry or deferred-removal fallback.

## Linux: target and table API

### Separate wire encoding from human formatting

- [ ] Replace `Display` as the table-parameter encoder with an explicit method
  on `Target`, such as `encode_params` or `write_params`.
- [ ] Ensure `Crypt` cannot expose key material through ordinary human-facing
  formatting. Keep its redacted `Debug` behavior.
- [ ] Preserve `TableBuilder::add_raw` for dmsetup-style input and out-of-tree
  targets.

### Simplify public row vocabulary without losing mode safety

- [ ] Expose concrete `TableRow` and `TargetStatusRow` names. The generic
  `Row<M>` implementation and sealed mode markers may remain internal.
- [ ] Consider clearer operation names such as `device_status` and
  `target_status`; the current `Device::status`/`Device::info` distinction is
  easy to reverse.
- [ ] Keep separate `Target::Table` and `Target::Info` associated types.
  dm-integrity genuinely has a read-back table shape different from its write
  shape.

### Standardize target construction

- [ ] Document one construction policy: public fields for plain wire records;
  private fields plus validating constructors for cross-field invariants.
- [ ] Replace standalone infallible builders whose `build()` cannot fail with
  `new(required_fields).with_*()` methods, or make their validation real.
- [ ] Align shared verity vocabulary across crates (`data_blocks`,
  `root_hash`, block sizes, version, hash start, and layout).

### Narrow destructive helpers

- [ ] Reconsider the public `linux::format::zero_metadata(path, bytes)` API.
  Prefer a target-specific operation or a fixed-size `clear_metadata_block`
  helper so callers cannot accidentally request an arbitrary overwrite range.

## Documentation and workspace maintenance

- [ ] Rewrite or drastically reduce `linux/README.md`. It currently uses the
  old crate name, references nonexistent `devmap::Error` and `Verity::new`,
  treats `DevId::new` as infallible, omits `Target::Table`, and describes stale
  runtime status types.
- [ ] Remove stale claims that `crypt` is unmodelled from `table.rs` and
  `targets/mod.rs`.
- [ ] Keep create/load/resume as separate low-level Linux operations. If the
  root CLI wants a common activation sequence, put that policy in a private CLI
  helper with explicit rollback behavior.
- [ ] Do not add per-target Cargo features to `devmap-linux`; the conditional
  API and test matrix would cost more than the dependency savings.
- [ ] Optionally set workspace `default-members` to `linux` and `verity` while
  retaining every member and continuing to test `--workspace` in CI.
- [ ] Remove the root package's duplicate `devmap-linux` dev-dependency; it is
  already a normal dependency.

## Decisions to preserve

- [ ] Keep `Control` as the subsystem factory and `Device` as a cheap,
  non-destructive device handle.
- [ ] Keep explicit removal; do not restore `Drop`-based kernel-state cleanup.
- [ ] Keep table load and resume separate because they represent inactive and
  active kernel table states.
- [ ] Keep the open `Target` trait, typed target status, and raw escape hatches.
- [ ] Keep `io::Result` at ioctl boundaries so kernel errno remains available.
- [ ] Keep consuming, single-use `TableBuilder`; unlike consuming `Device`, its
  ownership model prevents accidental reuse after load.

## Verification status

At the time of the original review, with no review-driven code changes:

- `cargo test -p devmap-linux -p devmap-verity` passed.
- `cargo check --workspace --all-targets` passed.

After completing the audited removals:

- `cargo check --workspace --all-targets` passes.
- `cargo test -p devmap-verity --all-targets` passes.
- `cargo test --workspace --all-targets` passes.
- `cargo clippy --workspace --all-targets -- -D warnings` passes.
- `RUSTDOCFLAGS='-D warnings' cargo doc -p devmap-verity --no-deps` passes.
- `cargo fmt --all -- --check` and `git diff --check` pass.
