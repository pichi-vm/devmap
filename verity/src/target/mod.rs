// SPDX-License-Identifier: Apache-2.0

//! Linux dm-verity target descriptions and activation policy.

use devmap_core::{BlockSize, Geometry};
use devmap_linux::{DevId, targets::Version};

use crate::header::{Algorithm, Constraint, HashType, Salt};

mod builder;
mod codec;
mod info;
mod policy;

pub use builder::Builder;
pub use info::Info;
pub use policy::{CorruptionPolicy, IoErrorPolicy};

/// A validated Linux dm-verity table description.
///
/// Construct through [`Verity::builder`] or
/// [`Header::builder`](crate::header::Header::builder). The root must come
/// from an independently trusted source. Activate in a read-only table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verity {
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

impl Verity {
    /// Returns the full row length in 512-byte sectors.
    pub const fn data_sectors(&self) -> u64 {
        self.data_sectors
    }

    fn supports_version(&self, version: Version) -> bool {
        let release = (version.major, version.minor, version.patch);
        version.major == 1
            && (!matches!(
                self.corruption_policy,
                CorruptionPolicy::Ignore | CorruptionPolicy::Restart
            ) || release >= (1, 2, 0))
            && (!self.ignore_zero_blocks || release >= (1, 3, 0))
            && (!self.check_at_most_once || release >= (1, 4, 0))
            && (self.signature.is_none() || release >= (1, 5, 0))
            && (self.corruption_policy != CorruptionPolicy::Panic || release >= (1, 7, 0))
            && (!self.try_verify_in_tasklet || release >= (1, 9, 0))
            && (self.io_error_policy == IoErrorPolicy::Error || release >= (1, 10, 0))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::num::NonZero;

    use devmap_linux::{targets::Parse, targets::Target};

    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)] // Version-boundary fixtures for independent target options.
    fn version_gates_optional_verity_parameters() {
        let data = DevId::new(252, 1).unwrap();
        let hash = DevId::new(252, 2).unwrap();
        let base = Verity::builder(data, hash, NonZero::new(1).unwrap(), vec![0; 32])
            .unwrap()
            .build();

        let cases = [
            (
                Verity {
                    corruption_policy: CorruptionPolicy::Ignore,
                    ..base.clone()
                },
                [1, 1, 0],
                [1, 2, 0],
            ),
            (
                Verity {
                    corruption_policy: CorruptionPolicy::Restart,
                    ..base.clone()
                },
                [1, 1, 0],
                [1, 2, 0],
            ),
            (
                Verity {
                    ignore_zero_blocks: true,
                    ..base.clone()
                },
                [1, 2, 0],
                [1, 3, 0],
            ),
            (
                Verity {
                    check_at_most_once: true,
                    ..base.clone()
                },
                [1, 3, 0],
                [1, 4, 0],
            ),
            (
                Verity {
                    signature: Some("test-key".into()),
                    ..base.clone()
                },
                [1, 4, 0],
                [1, 5, 0],
            ),
            (
                Verity {
                    corruption_policy: CorruptionPolicy::Panic,
                    ..base.clone()
                },
                [1, 6, 0],
                [1, 7, 0],
            ),
            (
                Verity {
                    try_verify_in_tasklet: true,
                    ..base.clone()
                },
                [1, 8, 0],
                [1, 9, 0],
            ),
            (
                Verity {
                    io_error_policy: IoErrorPolicy::Restart,
                    ..base.clone()
                },
                [1, 9, 0],
                [1, 10, 0],
            ),
            (
                Verity {
                    io_error_policy: IoErrorPolicy::Panic,
                    ..base.clone()
                },
                [1, 9, 0],
                [1, 10, 0],
            ),
        ];

        assert!(
            base.encode(
                Version {
                    major: 1,
                    minor: 0,
                    patch: 0
                },
                &mut Vec::new()
            )
            .is_ok()
        );
        assert!(
            base.encode(
                Version {
                    major: 2,
                    minor: 0,
                    patch: 0
                },
                &mut Vec::new()
            )
            .is_err()
        );

        for (target, before, minimum) in cases {
            let [major, minor, patch] = before;
            let before = Version {
                major,
                minor,
                patch,
            };
            let [major, minor, patch] = minimum;
            let minimum = Version {
                major,
                minor,
                patch,
            };
            assert!(
                matches!(target.encode(before, &mut Vec::new()), Err(error) if error.kind() == io::ErrorKind::Unsupported)
            );
            assert!(target.encode(minimum, &mut Vec::new()).is_ok());

            let mut bytes = Vec::new();
            target.encode(minimum, &mut bytes).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            let error = Verity::parse(&text, before).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(Verity::parse(&text, minimum).unwrap(), target);
        }
    }
}
