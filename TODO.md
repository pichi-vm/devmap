# API review backlog

Current ownership and workflows are described in [MIGRATION.md](MIGRATION.md)
and each crate's API documentation. [STYLE.md](STYLE.md) records the repository's
design rules. The questions below are unresolved review work, not descriptions
of supported APIs or approval to change them.

## Verity coverage and decoding

- [ ] Expand reference-tool coverage across the supported data/hash block-size
  combinations and digest sizes. Header tests exercise all accepted block sizes
  and both hash types; formatting tests cover both salt conventions, and
  interoperability tests cover representative layouts and available algorithms.
  Those checks do not establish every combination against veritysetup or Linux.
- [ ] Decide whether callers need to distinguish well-formed but unsupported
  headers from malformed headers. `Hashes::open` currently rejects unknown
  algorithms and versions with `InvalidData`, while accepting known algorithms
  whose hashing implementations are disabled. Do not add a public raw-record
  API without a concrete inspection requirement.

## Linux parsing and device handles

- [ ] Preserve the difference between an unrelated row and malformed parameters
  for a matching target. `Row::parse::<T>()` currently returns `None` for either;
  `LiveTarget::info()` inherits that ambiguity. Review a fallible typed decoder
  while retaining `Row::params()` as the raw-text interface.
- [ ] Review whether `Control::by_node` is useful alongside
  `DevId::from_path` and `Control::by_device`. It already rejects regular
  files by delegating to `DevId::from_path`, but does not check whether the
  resulting block device is a live device-mapper mapping.
- [ ] Review borrowing versus consuming `Device::remove` and
  `Device::remove_deferred`. Both currently consume one handle even though
  other clones remain valid; callers need a retained clone for a retry.
- [ ] Review whether concrete names for table rows and target-status rows would
  improve discoverability. Keep the distinction between table parameters,
  per-target runtime status, and whole-device status.

## Target construction and encoding

- [ ] Review whether table encoding should remain `Display` or use an explicit
  encoding operation. Crypt table text can contain a raw key even though
  `Debug` redacts it; neither table text nor raw parameter strings are safe to
  log indiscriminately.
- [ ] Audit target constructors and builders against STYLE.md: keep fields
  private, reject invalid input at construction, and retain builders only when
  they serve a caller-visible purpose. Several target APIs still expose public
  fields or defer validation to the kernel.
- [ ] Review target parameter coverage against the kernel. Verity exposes its
  general block sizes, hash formats, offsets, and optional parameters, but that
  does not establish complete coverage for every other target crate.

## Workspace maintenance

- [ ] Remove the root package's duplicate `devmap-linux` dev-dependency; it is
  already a normal dependency.
- [ ] Decide whether workspace `default-members` would make local library work
  more convenient. Keep all members covered by workspace CI regardless.

## Verification

Use the commands in [MIGRATION.md](MIGRATION.md). Portable tests and compiling
examples do not establish kernel compatibility. The kernel test runner requires
device-mapper access; skipped tests must not be counted as kernel validation.
