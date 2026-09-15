#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests use private loop devices and never unload shared modules.
set -euo pipefail
cd "$(dirname "$0")/.."

kernel_runner=()
if test "$(id -u)" -ne 0; then kernel_runner=(sudo -n); fi
"${kernel_runner[@]}" test -r /dev/mapper/control
"${kernel_runner[@]}" test -w /dev/mapper/control

kernel_filter="${1:-.*}"
kernel_artifacts=$(cargo test -p devmap-linux --all-features --tests --no-run --message-format=json |
    jq -r --arg filter "$kernel_filter" 'select(.reason == "compiler-artifact" and .profile.test == true and .executable != null)
        | select(.target.name != "devmap_linux")
        | select(.target.name | test($filter))
        | [.target.name, .executable] | @tsv' | sort)
test -n "$kernel_artifacts"
while IFS=$'\t' read -r kernel_name kernel_executable; do
    printf 'Kernel test: %s\n' "$kernel_name"
    "${kernel_runner[@]}" "$kernel_executable" --nocapture --test-threads=1
done <<<"$kernel_artifacts"
