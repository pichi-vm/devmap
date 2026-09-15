// SPDX-License-Identifier: Apache-2.0
use devmap_core::parse::DevId;
use devmap_snapshot::dm as snapshot;
use devmap_zero::ZeroTarget;
#[test]
fn from_str_round_trips_trivial_targets() {
    assert_eq!("".parse::<ZeroTarget>(), Ok(ZeroTarget));
    assert_eq!(
        "252:1".parse::<snapshot::SnapshotOriginTarget>(),
        Ok(snapshot::SnapshotOriginTarget {
            origin: DevId::new(252, 1).unwrap()
        })
    );
}
#[test]
fn zero_rejects_non_empty_params() {
    assert!("junk".parse::<ZeroTarget>().is_err());
}
