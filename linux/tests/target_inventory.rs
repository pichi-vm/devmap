// SPDX-License-Identifier: Apache-2.0

use devmap_linux::target::Target as _;

#[test]
fn supported_kernel_targets_have_expected_owners() {
    let actual = [
        devmap_linux::target::crypt::CryptTarget::NAME,
        devmap_linux::target::snapshot::SnapshotTarget::NAME,
        devmap_linux::target::snapshot::SnapshotOriginTarget::NAME,
        devmap_linux::target::snapshot::SnapshotMergeTarget::NAME,
        devmap_linux::target::zero::ZeroTarget::NAME,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "crypt",
        "snapshot",
        "snapshot-origin",
        "snapshot-merge",
        "zero",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}
