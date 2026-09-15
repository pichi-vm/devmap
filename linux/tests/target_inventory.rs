// SPDX-License-Identifier: Apache-2.0

use devmap_core::Target as _;

#[test]
fn supported_kernel_targets_have_owner_crates() {
    let actual = [
        devmap_crypt::dm::CryptTarget::NAME,
        devmap_snapshot::dm::SnapshotTarget::NAME,
        devmap_snapshot::dm::SnapshotOriginTarget::NAME,
        devmap_snapshot::dm::SnapshotMergeTarget::NAME,
        devmap_verity::dm::VerityTarget::NAME,
        devmap_zero::dm::ZeroTarget::NAME,
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
