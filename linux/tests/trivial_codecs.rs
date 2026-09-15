// SPDX-License-Identifier: Apache-2.0
use devmap_core::DevId;
use devmap_snapshot::dm as snapshot;
use devmap_zero::dm::Target;
#[test]
fn from_str_round_trips_trivial_targets() {
    assert_eq!("".parse::<Target>(), Ok(Target));
    assert_eq!(
        "252:1".parse::<snapshot::Origin>(),
        Ok(snapshot::Origin {
            origin: DevId::new(252, 1).unwrap()
        })
    );
}
#[test]
fn zero_rejects_non_empty_params() {
    assert!("junk".parse::<Target>().is_err());
}
