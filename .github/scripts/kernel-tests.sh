#!/usr/bin/env bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Compile before publishing a fresh manifest or running any privileged tests.
set -euo pipefail

if (( $# < 1 )); then
  echo "Usage: $0 MANIFEST [RUNNER ...]" >&2
  exit 2
fi
manifest=$1
shift
runner=("$@")

# Invalidate previous runs before invoking Cargo, even if compilation fails.
rm -f -- "$manifest"
staging=$(mktemp -d "${manifest}.tmp.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT

# Do not pipe Cargo: its exit status must gate every subsequent operation.
cargo test --workspace --all-features --all-targets --no-run --message-format=json \
  > "$staging/messages.json"

# Require a complete, successful Cargo stream and a nonempty set of test
# executables. Reject paths that cannot be represented by a line manifest.
jq -ers '
  if (length > 0 and all(.[]; type == "object") and
      (.[-1].reason == "build-finished" and .[-1].success == true)) then
    [.[] | select(.reason == "compiler-artifact" and .profile.test == true and
                   .executable != null) | .executable] |
    if (length > 0 and all(.[];
        type == "string" and startswith("/") and
        (test("[\u0000\r\n]") | not))) then .[]
    else error("missing or invalid test executables") end
  else error("missing successful Cargo build-finished message") end
' "$staging/messages.json" | sort -u > "$staging/test-binaries"

while IFS= read -r executable; do
  if [[ ! -f "$executable" || ! -x "$executable" ]]; then
    echo "Test executable is missing or not executable: $executable" >&2
    exit 1
  fi
done < "$staging/test-binaries"

# Publish only after compilation AND validation succeed. The staging directory
# shares the manifest's filesystem so this rename is atomic.
mv -- "$staging/test-binaries" "$manifest"
while IFS= read -r executable; do
  echo "Running $executable"
  "${runner[@]}" "$executable" --include-ignored --test-threads=1
done < "$manifest"
