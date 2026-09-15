// SPDX-License-Identifier: Apache-2.0

use devmap_core::Target as _;

#[test]
fn every_existing_kernel_target_has_an_owner_crate() {
    let actual = [
        devmap_crypt::dm::Target::NAME,
        devmap_delay::dm::Target::NAME,
        devmap_dust::dm::Target::NAME,
        devmap_era::dm::Target::NAME,
        devmap_error::dm::Target::NAME,
        devmap_flakey::dm::Target::NAME,
        devmap_integrity::dm::Target::NAME,
        devmap_linear::dm::Target::NAME,
        devmap_log_writes::dm::Target::NAME,
        devmap_raid::dm::Target::NAME,
        devmap_snapshot::dm::Target::NAME,
        devmap_snapshot::dm::Origin::NAME,
        devmap_snapshot::dm::Merge::NAME,
        devmap_striped::dm::Target::NAME,
        devmap_thin::dm::Target::NAME,
        devmap_thin_pool::dm::Target::NAME,
        devmap_unstriped::dm::Target::NAME,
        devmap_verity::dm::Target::NAME,
        devmap_writecache::dm::Target::NAME,
        devmap_zero::dm::Target::NAME,
        devmap_zoned::dm::Target::NAME,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "crypt",
        "delay",
        "dust",
        "era",
        "error",
        "flakey",
        "integrity",
        "linear",
        "log-writes",
        "raid",
        "snapshot",
        "snapshot-origin",
        "snapshot-merge",
        "striped",
        "thin",
        "thin-pool",
        "unstriped",
        "verity",
        "writecache",
        "zero",
        "zoned",
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}
