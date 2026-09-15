#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."

package_metadata=$(cargo metadata --no-deps --format-version 1 --all-features)
jq -e '
  .packages as $packages |
  ($packages | map({key: .name, value: .}) | from_entries) as $by_name |
  def normal_deps($name):
    [$by_name[$name].dependencies[]? | select(.kind != "dev") | .name];
  def reaches_linux($name; $seen):
    if $name == "devmap-linux" then true
    elif ($seen | index($name)) != null then false
    else any(normal_deps($name)[]; reaches_linux(.; $seen + [$name])) end;
  ["crypt","snapshot","verity","zero"] | map("devmap-" + .) as $owners |
  (($packages | map(.name) | sort) ==
   (($owners + ["devmap-core", "devmap-linux", "devmap-luks"]) | sort)) and
  all($packages[].targets[]; (.kind | index("bin")) == null) and
  all($owners[]; $by_name[.] != null) and
  all(($owners + ["devmap-luks"])[];
      any($by_name[.].dependencies[];
          .name == "devmap-core" and .kind == null and .optional == false)) and
  all($packages[];
      [.dependencies[] | select(.optional) | (.rename // .name)] as $optional |
      all(.features | keys[];
          . as $feature | $feature == "default" or ($optional | index($feature)) != null)) and
  all($packages[] | select(.name != "devmap-linux");
      reaches_linux(.name; []) | not) and
  ([normal_deps("devmap-linux")[] | select(startswith("devmap-"))] == ["devmap-core"])
' <<<"$package_metadata"

metadata_tree=$(cargo tree -p devmap-verity --no-default-features --edges normal --prefix none)
rg -q '^devmap-core v' <<<"$metadata_tree"
if rg '^(devmap-linux|tokio|digest|sha1|sha2|sha3|ripemd|whirlpool|streebog|sm3|blake2) v' <<<"$metadata_tree"; then
    echo "verity minimal header/target build contains an unexpected implementation dependency" >&2
    exit 1
fi
crypt_tree=$(cargo tree -p devmap-luks --no-default-features --edges normal --prefix none)
if rg '^devmap-crypt v' <<<"$crypt_tree"; then
    echo "LUKS crypt-target conversion must remain optional" >&2
    exit 1
fi
test ! -e linux/src/targets/mod.rs
snapshot_tree=$(cargo tree -p devmap-snapshot --all-features --edges normal --prefix none)
if rg '^rustix v' <<<"$snapshot_tree"; then
    echo "snapshot/core must not depend on application sparse-file support" >&2
    exit 1
fi
