// SPDX-License-Identifier: Apache-2.0

/// Version reported by the kernel for one device-mapper target type.
///
/// These are target-specific numbers, not a semantic-versioning promise.
/// Compare versions only within the same target type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl From<[u32; 3]> for Version {
    fn from([major, minor, patch]: [u32; 3]) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}
