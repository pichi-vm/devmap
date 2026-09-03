# Repository style guide

This guide records the design and review conventions used in this repository.
It applies to every workspace crate. Existing code may not follow every rule
yet; new code and substantial revisions should.

## General approach

- Prefer a small, unsurprising API over a flexible-looking API with redundant
  ways to perform the same operation.
- Use Rust's type system to make invalid states difficult or impossible to
  represent.
- Keep policy in the crate that owns it. Portable formats belong in their
  format crates, Linux interfaces belong in `devmap-linux`, and application
  policy belongs in the CLI or its caller.
- Support the full meaningful parameter space of a format. Do not simplify an
  implementation by silently reducing a general format to one profile.
- Remove types, methods, constants, and abstractions that do not carry their
  weight. A test-only use does not by itself justify public API.
- Prefer standard-library and established ecosystem traits over project-local
  equivalents.
- Do not use `unsafe` code. The workspace denies it.

## Public API

Treat every public item as a long-term compatibility commitment.

- Expose the concepts callers need, not storage details or intermediate
  implementation state.
- Keep fields private. Use accessors where callers need semantic values.
- Do not add accessors merely because a field exists. In particular, omit
  choices for which the format currently permits only one value.
- Use `#[non_exhaustive]` on public enums when the underlying format may gain
  more values.
- Add `#[must_use]` when ignoring a value is likely to be a mistake, especially
  for builders and unfinished streaming adapters.
- Prefer standard conversions:
  - `From` for infallible conversions.
  - `TryFrom` for validation.
  - `FromStr` for parsing names.
  - `AsRef` for cheap borrowed views.
- Provide borrowed conversions for large values when conversion does not need
  ownership. An owned conversion may delegate to the borrowed one.
- Do not add convenience methods that only rename an existing trait operation,
  such as `as_u32` or `as_bytes`, unless they make an important semantic
  distinction.
- Keep private traits and blanket implementations limited to their actual
  callers. Do not implement combinations speculatively.
- Derive ordinary value traits when their semantics are structural. Write a
  manual `Debug`, equality, or hashing implementation only when the derived
  behavior would be misleading or disclose something it should not.
- Avoid `Copy` on large records when an implicit copy would hide meaningful
  cost.

Before adding a public item, ask:

1. Does a caller need this concept?
2. Is a standard trait already the natural API?
3. Can the operation produce an invalid value?
4. Does another public operation already provide the same capability?
5. Will this item still make sense if the supported format grows?

## Validity and construction

Semantic values should be valid by construction.

- Validate caller input when it enters a builder or constructor. Do not store
  an invalid value and defer an independent check until `build`.
- Leave only genuinely cross-field checks for `build`.
- Pass required identity values to `build` when they have no useful default.
  UUIDs and data sizes are examples.
- Give fields defaults only when the default is conventional and useful.
  Examples should set only values that differ from those defaults.
- Use separate types for untrusted encoded bytes and validated semantic data.
  Name the distinction plainly, such as `Unverified` and `Verified`.
- Conversion from an untrusted representation to a semantic value must be
  fallible and complete. Once converted, downstream code must not repeat the
  same validation.
- Convert semantic values back to their encoded form with `From` when every
  semantic value has one canonical encoding.
- Do not keep a copy of the encoded representation inside the semantic value
  solely to make serialization convenient.

Choose a dedicated newtype only when it enforces an invariant, supplies useful
behavior, or prevents confusion between otherwise identical values. Remove it
when validation has moved to a stronger construction boundary and the wrapper
no longer adds safety. Use enums for closed sets of semantic choices.

Use `Option` only when absence is the complete result. Use `Result` when a
caller needs to know that a supplied value or encoded record was invalid.

## Modules and files

- Use `mod.rs` modules throughout this repository.
- Give each substantial public or domain type a focused file when practical.
- Keep small, closely related private state types together in their owning
  module. One tiny internal enum per file makes control flow harder to follow.
- Use short filenames that name the concept directly, such as `sync.rs`,
  `async.rs`, or `state.rs`.
- Put behavior with the type that owns the decision. For example, selection of
  a hash implementation belongs with the algorithm, not in an unrelated tree
  module.
- Avoid freestanding functions when the operation naturally belongs to a
  type or trait.
- Inline a small helper when it has one caller and naming it does not clarify a
  separate concept. Do not create helpers merely to hide a few expressions.
  Shared nontrivial logic should still have one implementation.

## Data representation

- Use slices and fixed-size arrays when the format has a fixed capacity. Avoid
  `Vec` when allocation provides no benefit.
- Prefer associated constants on the type they describe over unrelated module
  constants.
- Use the canonical names and numeric values understood by Linux. Do not
  invent friendlier aliases in an on-disk or kernel-facing representation.
- Group enum variants by family and keep matching arms in the same order as
  the variants.
- Keep format metadata available even when an optional implementation is not
  compiled. For example, an algorithm can remain representable and parseable
  while tree construction reports that its hashing feature is unavailable.
- Do not mirror a dependency's type family with a large local enum solely to
  erase concrete types. Prefer its object-safe trait, such as `DynDigest`, and
  expose plain bytes when the format itself treats the result as bytes.

For fixed binary records:

- Use a byte-exact representation when it makes the layout clearer. Zerocopy
  is appropriate for plain fixed-layout records, but not as a substitute for
  semantic validation.
- Represent byte order explicitly. Never rely on the host's native endianness
  for an on-disk or kernel format.
- Assert record sizes and significant field offsets at compile time.
- Keep record bytes separate from alignment or block padding. A 512-byte
  record remains a 512-byte record even when it occupies a larger block.
- Require canonical encodings when writing. If reading is stricter than an
  external implementation, document and test that policy.

## Builders

- Name the type `Builder` inside its module unless a more specific public name
  prevents ambiguity.
- Builder setters should consume and return `Self`.
- Infallible setters should be `const fn` when doing so is simple and useful.
- Fallible setters should reject bad values immediately and return the updated
  builder only on success.
- Use direct units in APIs. Accept a block size in bytes when callers think in
  bytes; do not require its base-two order solely to simplify implementation.
- Keep error messages stable within a validation path and avoid redeclaring
  them while changing an error's kind.

## I/O and streaming

Use the standard I/O traits as the public protocol.

- Implement `Read`, `Write`, and `Seek`, or their `futures-io` counterparts,
  when a type behaves like an I/O adapter.
- Give synchronous and asynchronous users the same types and workflow. The
  implemented traits should differ, not the conceptual API.
- Prefer the runtime-neutral `futures-io` traits for library-facing async I/O.
  Do not add parallel sync and async inherent-method APIs for the same
  operation.
- Separate representation and validation from transport. If a fixed record can
  be exposed as bytes, let callers use the appropriate sync or async I/O trait
  to transfer those bytes.
- Take an input or output by value when the adapter owns it. Callers can pass
  `&mut W` when they want to retain the underlying value.
- Stream data with bounded memory. Do not accumulate an entire image or hash
  tree when one block per active level is sufficient.
- Retain `Seek` when the format genuinely requires nonsequential output. Do
  not remove it by replacing bounded state with unbounded buffering.
- Prefer `io::copy`, `repeat`, `take`, and `sink` to allocation or manual
  buffer loops when they express the operation directly.
- Use `read_exact` and `write_all` for fixed fields.
- Do not use `expect`, `unwrap`, or runtime assertions for values derived from
  input or I/O. Return an error.

### Completion and failure

- Make stream completion observable. If a root digest is meaningful only after
  completion, return it only then.
- `flush` may complete a final partial block when that is the format's natural
  meaning. Document when this seals the writer and prevents later writes.
- Never rely on `Drop` for a fallible finalization step. Dropping an unfinished
  adapter must not pretend that output was completed.
- After a downstream output failure, poison the adapter if continuing could
  corrupt the result.
- Keep caller-correctable state errors recoverable when retrying is safe.
- Asynchronous operations must remain correct after `Poll::Pending`; store
  enough typed internal state to resume the same operation without repeating
  accepted input or emitted output.

## Errors

- Use `io::Error` for APIs whose failures are input validation, decoding, or
  I/O in one operation. Add a custom error type only when callers need stable,
  structured distinctions that `io::ErrorKind` cannot express.
- Select a meaningful kind:
  - `InvalidInput` for bad caller-supplied construction parameters.
  - `InvalidData` for malformed or unsupported encoded data.
  - `Unsupported` when valid metadata names an implementation excluded at
    compile time.
  - `UnexpectedEof` when declared input is incomplete.
  - `WouldBlock` when another required operation, such as a final flush, has
    not happened.
  - `BrokenPipe` when a completed stream rejects more input.
- Do not collapse every internal failure into `Other`.
- When changing an error's kind at a boundary, retain the original error as
  the payload instead of repeating and possibly changing its text.

## Cargo features

- Make optional implementation dependencies optional Cargo dependencies.
  Cargo provides their same-named features automatically; do not redeclare
  those features without additional behavior to group.
- Keep default features small and useful. `devmap-verity`, for example,
  defaults to the SHA-2 family rather than every supported algorithm.
- Do not conditionally compile semantic format variants merely because their
  implementation dependency is optional.
- Mark feature-gated public API with docs.rs `doc(cfg(...))` annotations.
- Test every optional dependency by itself, no-default-features builds, and the
  all-features build.

## Documentation

Write documentation for someone using the crate for the first time.

- Use plain, direct English. Keep it humble and brief.
- Explain what the type or operation does, the invariants callers must honor,
  and the errors they can act on.
- Do not describe development history, discarded designs, or why the current
  code replaced an older implementation.
- Do not spend prose listing trait implementations already visible in generated
  API documentation.
- Start crate documentation with a short introduction, then show the main
  workflows in the order callers need them.
- For I/O crates, show reading and writing, including both synchronous and
  asynchronous forms when supported. Emphasize that the workflow and types are
  the same and only the I/O traits differ.
- Comment example code by step. Each comment should explain an action the
  caller needs to understand.
- Keep examples minimal and executable. Use defaults rather than spelling them
  out, and test examples as doctests.
- Document format-sensitive behavior such as padding, alignment, stream
  position, and whether input storage must include a padded final block.
- Use intra-doc links for related types and operations.

## Tests and release checks

Test contracts at the narrowest useful boundary.

- Put public API behavior in integration tests.
- Keep unit tests for private state and implementation details that cannot be
  observed clearly through the public API.
- Give compatibility with an external reference implementation its own test
  target.
- Compare binary formats byte for byte against the authoritative
  implementation where possible. For Linux formats, test the parameter
  combinations most likely to expose layout differences, not only defaults.
- Test valid boundaries, invalid boundaries, arithmetic overflow, truncated
  input, malformed padding, disabled features, and downstream I/O failures.
- Test synchronous and asynchronous behavior independently, including short
  operations, cancellation, retries, seek failures, flush failures, and
  poisoning after fatal errors.
- A new algorithm or format mode needs a focused interoperability fixture.
- Coverage identifies missing cases; it is not a reason to expose internals or
  add tests that cannot catch a real regression.

Before release, run at least:

```console
cargo fmt --all --check
cargo test --workspace --all-features --all-targets
cargo test --workspace --no-default-features --all-targets
cargo test --workspace --all-features --doc
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo doc --workspace --all-features --no-deps
cargo package -p <crate>
```

Also build with the declared minimum Rust version, inspect the packaged file
list, verify license and README inclusion, and run any required external
compatibility tools in CI.

## Source style

- Begin Rust source files with the repository SPDX header:

  ```rust
  // SPDX-License-Identifier: Apache-2.0
  ```

- Use `cargo fmt`; do not hand-format against it.
- Follow the workspace lints and keep Clippy clean with warnings denied before
  release.
- Prefer early returns when they make the successful path direct.
- Avoid comments that restate the code. Comment invariants, format rules, and
  non-obvious safety or compatibility constraints.
- Preserve unrelated work in a dirty tree. Keep each change within the scope
  being reviewed.
