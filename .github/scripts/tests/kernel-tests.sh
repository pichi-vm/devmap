#!/usr/bin/env bash
# SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

# Safe regression fixtures only: no real Cargo, sudo, or kernel operations.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sandbox=$(mktemp -d)
trap 'rm -rf -- "$sandbox"' EXIT
mkdir -p "$sandbox/bin"
export FIXTURE_ROOT=$sandbox
export PATH="$sandbox/bin:$PATH"

cat > "$sandbox/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'test --workspace --all-features --all-targets --no-run --message-format=json' ]]
artifact=$(jq -cn --arg path "$FIXTURE_ROOT/test executable" \
  '{reason:"compiler-artifact", package_id:"path+file:///fixture#fixture@0.1.0", target:{name:"fixture", kind:["test"]}, profile:{test:true}, executable:$path, fresh:false}')
case "$FIXTURE_CASE" in
  compiler-failure)
    printf '%s\n' "$artifact"
    printf '%s\n' '{"reason":"compiler-message","message":{"level":"error","message":"could not compile crypto fixture"}}' '{"reason":"build-finished","success":false}'
    echo 'error: could not compile crypto fixture' >&2
    exit 101 ;;
  unsuccessful) printf '%s\n' "$artifact" '{"reason":"build-finished","success":false}' ;;
  malformed) printf '%s\n' "$artifact" 'not JSON' ;;
  empty) : ;;
  no-artifacts) printf '%s\n' '{"reason":"build-finished","success":true}' ;;
  truncated) printf '%s\n' "$artifact" ;;
  invalid-path)
    jq -cn '{reason:"compiler-artifact", profile:{test:true}, executable:"/bad\npath"}'
    printf '%s\n' '{"reason":"build-finished","success":true}' ;;
  missing-file)
    jq -cn '{reason:"compiler-artifact", profile:{test:true}, executable:"/nonexistent/kernel-test-fixture"}'
    printf '%s\n' '{"reason":"build-finished","success":true}' ;;
  success)
    printf '%s\n' "$artifact" "$artifact" '{"reason":"build-finished","success":true}' ;;
  *) exit 2 ;;
esac
CARGO
cat > "$sandbox/test executable" <<'TEST'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == '--include-ignored --test-threads=1' ]]
printf 'test ran\n' >> "$FIXTURE_ROOT/executed"
TEST
cat > "$sandbox/bin/runner" <<'RUNNER'
#!/usr/bin/env bash
set -euo pipefail
printf 'runner ran\n' >> "$FIXTURE_ROOT/runner-executed"
exec "$@"
RUNNER
chmod +x "$sandbox/bin/cargo" "$sandbox/bin/runner" "$sandbox/test executable"

manifest="$sandbox/test-binaries"
for case in compiler-failure unsuccessful malformed empty no-artifacts truncated invalid-path missing-file; do
  export FIXTURE_CASE=$case
  # A stale, valid executable must never survive a failed compilation or parse.
  printf '%s\n' "$sandbox/test executable" > "$manifest"
  # Match Actions' bash -e caller, deliberately without inherited pipefail.
  if bash -e "$script_dir/kernel-tests.sh" "$manifest" runner > "$sandbox/output" 2>&1; then
    echo "FAIL: $case unexpectedly succeeded" >&2
    cat "$sandbox/output" >&2
    exit 1
  else
    status=$?
  fi
  if [[ "$case" == compiler-failure ]]; then
    [[ $status == 101 ]]
  fi
  [[ ! -e "$manifest" && ! -e "$sandbox/executed" && ! -e "$sandbox/runner-executed" ]]
  shopt -s nullglob
  leftovers=("$manifest".tmp.*)
  [[ ${#leftovers[@]} == 0 ]]
  printf 'PASS: %s rejects stale/partial tests and cleans staging\n' "$case"
done

export FIXTURE_CASE=success
printf '/stale/binary\n' > "$manifest"
bash -e "$script_dir/kernel-tests.sh" "$manifest" runner
[[ $(cat "$manifest") == "$sandbox/test executable" ]]
[[ $(cat "$sandbox/executed") == 'test ran' ]]
[[ $(cat "$sandbox/runner-executed") == 'runner ran' ]]
printf 'PASS: success publishes a fresh deduplicated manifest and runs tests once\n'
