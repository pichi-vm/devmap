// SPDX-License-Identifier: Apache-2.0

//! The `raid` target: software RAID over a set of devices, bridging to the
//! kernel's MD raid personalities.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// One `(metadata device, data device)` pair of a [`Raid`] mapping.
/// `metadata` of `None` renders as `-` (no dedicated metadata device
/// for that slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePair {
    /// Optional dedicated metadata device for this slot; `None` renders as
    /// `-` (no separate metadata device).
    pub metadata: Option<DevId>,
    /// The data device for this slot.
    pub data: DevId,
}

impl DevicePair {
    /// A pair with a dedicated metadata device.
    #[must_use]
    pub fn new(metadata: Option<DevId>, data: DevId) -> Self {
        Self { metadata, data }
    }

    /// A pair with no dedicated metadata device (renders `-` for
    /// metadata).
    #[must_use]
    pub fn data_only(data: DevId) -> Self {
        Self {
            metadata: None,
            data,
        }
    }
}

/// [`Raid`]'s raid level. `Raid5`/`Raid6` use the conventional default
/// parity layouts (`raid5_ls`, `raid6_zr`); for other layout suffixes
/// (`_la`/`_ra`/`_rs`/`_n`, ...) use a user-defined target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Type {
    /// Striping with no redundancy.
    Raid0,
    /// Mirroring across all devices.
    Raid1,
    /// Striping with a dedicated parity device.
    Raid4,
    /// Striping with distributed single parity.
    Raid5,
    /// Striping with distributed double parity.
    Raid6,
    /// Striped mirrors (combined RAID1 and RAID0).
    Raid10,
}

/// Software RAID, bridging to the kernel's MD raid personalities. Only
/// the mandatory `chunk_size` raid parameter is exposed; sync control,
/// rebuild indices, and journal devices are locked out.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
// `raid_type` reads redundantly against the `Raid` struct name, but it is
// the natural term for the field and its public accessor.
#[allow(clippy::struct_field_names)]
pub struct Raid {
    raid_type: Type,
    chunk_size_sectors: u64,
    devices: Vec<DevicePair>,
}
impl Raid {
    /// Construct a [`Raid`].
    ///
    /// For [`Type::Raid1`] the kernel ignores the chunk size, so any
    /// argument is coerced to `0`.
    #[must_use]
    pub fn new(raid_type: Type, chunk_size_sectors: u64, devices: Vec<DevicePair>) -> Self {
        let chunk_size_sectors = if raid_type == Type::Raid1 {
            // raid1 has no stripes; the kernel ignores (and rejects a
            // non-zero) chunk size, so normalize to 0.
            0
        } else {
            chunk_size_sectors
        };
        Raid {
            raid_type,
            chunk_size_sectors,
            devices,
        }
    }

    /// The raid level.
    #[must_use]
    pub fn raid_type(&self) -> Type {
        self.raid_type
    }
    /// The chunk size in sectors (`0` for raid1).
    #[must_use]
    pub fn chunk_size_sectors(&self) -> u64 {
        self.chunk_size_sectors
    }
    /// The device pairs backing this mapping.
    #[must_use]
    pub fn devices(&self) -> &[DevicePair] {
        &self.devices
    }
}
impl Target for Raid {
    const TYPE_NAME: &'static str = "raid";
    type Info = RawInfo;
}
impl fmt::Display for Raid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raid_type = match self.raid_type {
            Type::Raid0 => "raid0",
            Type::Raid1 => "raid1",
            Type::Raid4 => "raid4",
            // The kernel's raid_types[] has no bare "raid5"/"raid6"; emit the
            // conventional default parity layouts it does accept.
            Type::Raid5 => "raid5_ls",
            Type::Raid6 => "raid6_zr",
            Type::Raid10 => "raid10",
        };
        // `<chunk_size>` is a bare positional number, not a
        // `chunk_size <value>` keyword pair — confirmed against
        // dm-raid.c's `parse_raid_params`. `#raid_params` is therefore 1.
        write!(
            f,
            "{raid_type} 1 {} {}",
            self.chunk_size_sectors,
            self.devices.len()
        )?;
        for pair in &self.devices {
            match pair.metadata {
                Some(metadata) => write!(f, " {metadata}")?,
                None => f.write_str(" -")?,
            }
            write!(f, " {}", pair.data)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn raid_renders_type_chunk_size_and_device_pairs() {
        // raid1 ignores chunk size: the argument is coerced to 0.
        let t = Raid::new(
            Type::Raid1,
            128,
            vec![
                DevicePair::new(None, DevId::new(252, 1)),
                DevicePair::new(Some(DevId::new(252, 2)), DevId::new(252, 3)),
            ],
        );
        assert_eq!(
            line(0, 1_048_576, &t),
            "0 1048576 raid raid1 1 0 2 - 252:1 252:2 252:3"
        );
    }

    fn devs(n: u32) -> Vec<DevicePair> {
        (0..n)
            .map(|i| DevicePair::data_only(DevId::new(252, i)))
            .collect()
    }

    #[test]
    fn raid_renders_each_type_token() {
        // raid5/raid6 render the kernel's default layout suffix, not a bare name.
        for (ty, token, n) in [
            (Type::Raid0, "raid0", 1),
            (Type::Raid4, "raid4", 2),
            (Type::Raid5, "raid5_ls", 2),
            (Type::Raid6, "raid6_zr", 3),
            (Type::Raid10, "raid10", 2),
        ] {
            let t = Raid::new(ty, 8, devs(n));
            assert!(
                line(0, 1024, &t).contains(&format!("raid {token} 1 8 ")),
                "{token}"
            );
        }
    }

    #[test]
    fn raid_device_pair_constructors() {
        assert_eq!(
            DevicePair::data_only(DevId::new(252, 1)),
            DevicePair {
                metadata: None,
                data: DevId::new(252, 1)
            }
        );
        assert_eq!(
            DevicePair::new(Some(DevId::new(252, 2)), DevId::new(252, 3)),
            DevicePair {
                metadata: Some(DevId::new(252, 2)),
                data: DevId::new(252, 3)
            }
        );
    }
}
