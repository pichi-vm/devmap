// SPDX-License-Identifier: Apache-2.0

use devmap_core::Target as _;

#[test]
fn supported_kernel_targets_have_owner_crates() {
    let actual = [
        devmap_crypt::dm::Target::NAME,
        devmap_snapshot::dm::Target::NAME,
        devmap_snapshot::dm::Origin::NAME,
        devmap_snapshot::dm::Merge::NAME,
        devmap_verity::dm::Target::NAME,
        devmap_zero::dm::Target::NAME,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "crypt",
        "snapshot",
        "snapshot-origin",
        "snapshot-merge",
        "verity",
        "zero",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}
