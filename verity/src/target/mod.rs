// SPDX-License-Identifier: Apache-2.0

//! Linux dm-verity target descriptions and activation policy.

use crate::header::{Algorithm, Constraint, HashType, Salt};
use devmap_core::{BlockSize, Geometry};
use devmap_linux::{
    DevId,
    table::TableMode,
    target::{EncodeError, Parse, Target, Version},
};

mod builder;
mod codec;
mod info;
mod policy;
pub use builder::Builder;
pub use info::Info;
pub use policy::{CorruptionPolicy, IoErrorPolicy};

/// A validated Linux dm-verity table description.
///
/// Construct through [`VerityTarget::builder`] or
/// [`Header::builder`](crate::header::Header::builder). The root must come
/// from an independently trusted source. Activate in a read-only table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerityTarget {
    hash_type: HashType,
    data: DevId,
    hash: DevId,
    geometry: Geometry<Constraint>,
    block: BlockSize<Constraint>,
    hash_start: u64,
    algorithm: Algorithm,
    salt: Salt,
    corruption_policy: CorruptionPolicy,
    io_error_policy: IoErrorPolicy,
    ignore_zero_blocks: bool,
    check_at_most_once: bool,
    try_verify_in_tasklet: bool,
    signature: Option<String>,
    root: Box<[u8]>,
    data_sectors: u64,
}

impl VerityTarget {
    /// Returns the full row length in 512-byte sectors.
    pub const fn data_sectors(&self) -> u64 {
        self.data_sectors
    }

    fn supports_version(&self, version: Version) -> bool {
        version.major == 1
            && (!matches!(
                self.corruption_policy,
                CorruptionPolicy::Ignore | CorruptionPolicy::Restart
            ) || version >= Version::from([1, 2, 0]))
            && (!self.ignore_zero_blocks || version >= Version::from([1, 3, 0]))
            && (!self.check_at_most_once || version >= Version::from([1, 4, 0]))
            && (self.signature.is_none() || version >= Version::from([1, 5, 0]))
            && (self.corruption_policy != CorruptionPolicy::Panic
                || version >= Version::from([1, 7, 0]))
            && (!self.try_verify_in_tasklet || version >= Version::from([1, 9, 0]))
            && (self.io_error_policy == IoErrorPolicy::Error
                || version >= Version::from([1, 10, 0]))
    }
}

impl Target for VerityTarget {
    const NAME: &'static str = "verity";
    type Table = Self;
    type Info = Info;

    fn encode(&self, version: Version) -> Result<String, EncodeError> {
        if !self.supports_version(version) {
            return Err(EncodeError { version });
        }
        Ok(self.to_string())
    }
}

impl Parse<TableMode> for VerityTarget {
    type Error = devmap_linux::ParseError;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        let target: Self = text.parse()?;
        if !target.supports_version(version) {
            return Err(devmap_linux::ParseError);
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use super::*;

    #[test]
    fn version_gates_optional_verity_parameters() {
        let data = DevId::new(252, 1).unwrap();
        let hash = DevId::new(252, 2).unwrap();
        let base = VerityTarget::builder(data, hash, NonZero::new(1).unwrap(), vec![0; 32])
            .unwrap()
            .build();

        let cases = [
            (
                VerityTarget {
                    corruption_policy: CorruptionPolicy::Ignore,
                    ..base.clone()
                },
                [1, 1, 0],
                [1, 2, 0],
            ),
            (
                VerityTarget {
                    corruption_policy: CorruptionPolicy::Restart,
                    ..base.clone()
                },
                [1, 1, 0],
                [1, 2, 0],
            ),
            (
                VerityTarget {
                    ignore_zero_blocks: true,
                    ..base.clone()
                },
                [1, 2, 0],
                [1, 3, 0],
            ),
            (
                VerityTarget {
                    check_at_most_once: true,
                    ..base.clone()
                },
                [1, 3, 0],
                [1, 4, 0],
            ),
            (
                VerityTarget {
                    signature: Some("test-key".into()),
                    ..base.clone()
                },
                [1, 4, 0],
                [1, 5, 0],
            ),
            (
                VerityTarget {
                    corruption_policy: CorruptionPolicy::Panic,
                    ..base.clone()
                },
                [1, 6, 0],
                [1, 7, 0],
            ),
            (
                VerityTarget {
                    try_verify_in_tasklet: true,
                    ..base.clone()
                },
                [1, 8, 0],
                [1, 9, 0],
            ),
            (
                VerityTarget {
                    io_error_policy: IoErrorPolicy::Restart,
                    ..base.clone()
                },
                [1, 9, 0],
                [1, 10, 0],
            ),
            (
                VerityTarget {
                    io_error_policy: IoErrorPolicy::Panic,
                    ..base.clone()
                },
                [1, 9, 0],
                [1, 10, 0],
            ),
        ];

        assert!(base.encode(Version::from([1, 0, 0])).is_ok());
        assert!(base.encode(Version::from([2, 0, 0])).is_err());

        for (target, before, minimum) in cases {
            let before = Version::from(before);
            let minimum = Version::from(minimum);
            assert_eq!(target.encode(before), Err(EncodeError { version: before }));
            assert!(target.encode(minimum).is_ok());

            let text = target.to_string();
            assert!(<VerityTarget as Parse<TableMode>>::parse(&text, before).is_err());
            assert_eq!(
                <VerityTarget as Parse<TableMode>>::parse(&text, minimum),
                Ok(target)
            );
        }
    }
}
