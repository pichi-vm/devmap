// SPDX-License-Identifier: Apache-2.0

//! Turning zone geometry into a dm-zoned metadata layout, and assembling
//! the metadata bytes. Pure computation — no device access.

use crate::{BLOCK_SIZE, FORMAT_VERSION, MAP_UNMAPPED, Superblock};

/// Zone geometry, as read from the device (see the crate's device module
/// for the `BLKREPORTZONE` query that fills this in).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Geometry {
    /// Total zones on the device.
    pub total_zones: u32,
    /// Blocks ([`BLOCK_SIZE`]) per zone — the zone size in 4 KiB blocks.
    pub zone_size_blocks: u32,
    /// Leading conventional (randomly-writable) zones. dm-zoned's metadata
    /// is rewritten in place, so it must live on these; the kernel puts
    /// the primary superblock in the first one.
    pub conventional_zones: u32,
}

/// Choices a caller can make at format time. [`Default`] fills in an empty
/// label, zero UUIDs, and a computed reserved-sequential count; a real
/// caller should set the UUIDs to distinct random values as `dmzadm` does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FormatOptions {
    /// The volume label, NUL-padded to 32 bytes.
    pub label: [u8; 32],
    /// The volume UUID. Must be non-zero: the kernel rejects a null UUID
    /// (`dmz_check_sb`), so a caller supplies one as `dmzadm` does — this
    /// crate does not invent randomness.
    pub dmz_uuid: [u8; 16],
    /// This device's UUID, distinct per device in a multi-device set. Must
    /// also be non-zero.
    pub dev_uuid: [u8; 16],
    /// Sequential zones to hold in reserve for reclaim. `None` uses a
    /// device-proportional default (one eighth of the sequential zones,
    /// at least one) — the value `dmzadm` also picks.
    pub reserved_seq: Option<u32>,
}

/// A geometry that can't host a dm-zoned volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LayoutError {
    /// Fewer than two conventional zones per metadata set are available.
    /// dm-zoned needs conventional zones for the primary and secondary
    /// metadata, so a purely sequential device cannot be formatted.
    NotEnoughConventionalZones {
        /// Conventional zones present.
        have: u32,
        /// Conventional zones the computed layout needs.
        need: u32,
    },
    /// After reserving metadata and sequential zones, no data zones are
    /// left — the device is too small.
    NoDataZones,
}

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LayoutError::NotEnoughConventionalZones { have, need } => write!(
                f,
                "dm-zoned needs {need} conventional zones for metadata, only {have} present"
            ),
            LayoutError::NoDataZones => f.write_str("device too small: no data zones remain"),
        }
    }
}

impl core::error::Error for LayoutError {}

/// The computed metadata layout for a device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Layout {
    geometry: Geometry,
    nr_meta_zones: u32,
    nr_meta_blocks: u32,
    nr_map_blocks: u32,
    nr_bitmap_blocks: u32,
    nr_chunks: u32,
    nr_reserved_seq: u32,
}

impl Layout {
    /// Compute the layout for `geometry`.
    ///
    /// The counts are mutually dependent — the metadata size sets how many
    /// zones it occupies, which sets how many data zones and chunks remain,
    /// which sets the mapping-table size, which feeds back into the
    /// metadata size — so this iterates to a fixed point (one step for any
    /// realistic device).
    ///
    /// # Errors
    ///
    /// [`LayoutError`] if the device has too few conventional zones for two
    /// metadata sets, or no data zones remain.
    pub fn compute(geometry: Geometry, options: &FormatOptions) -> Result<Self, LayoutError> {
        // One bitmap bit per block; the bitmap for every zone is stored,
        // rounded up to whole blocks (at least one per zone).
        let zone_bitmap_blocks = (geometry.zone_size_blocks / (8 * BLOCK_SIZE as u32)).max(1);
        let nr_bitmap_blocks = geometry.total_zones * zone_bitmap_blocks;

        let sequential_zones = geometry.total_zones - geometry.conventional_zones;
        let nr_reserved_seq = options
            .reserved_seq
            .unwrap_or_else(|| (sequential_zones / 8).max(1));

        let mut nr_meta_zones = 1u32;
        let (nr_chunks, nr_map_blocks, nr_meta_blocks) = loop {
            let meta_and_reserved = 2 * nr_meta_zones + nr_reserved_seq;
            if meta_and_reserved >= geometry.total_zones {
                return Err(LayoutError::NoDataZones);
            }
            let nr_chunks = geometry.total_zones - meta_and_reserved;
            let nr_map_blocks = nr_chunks.div_ceil(crate::MAP_ENTRIES_PER_BLOCK);
            let nr_meta_blocks = 1 + nr_map_blocks + nr_bitmap_blocks;
            let needed_zones = nr_meta_blocks.div_ceil(geometry.zone_size_blocks);
            if needed_zones == nr_meta_zones {
                break (nr_chunks, nr_map_blocks, nr_meta_blocks);
            }
            nr_meta_zones = needed_zones;
        };

        let need_conv = 2 * nr_meta_zones;
        if geometry.conventional_zones < need_conv {
            return Err(LayoutError::NotEnoughConventionalZones {
                have: geometry.conventional_zones,
                need: need_conv,
            });
        }

        Ok(Layout {
            geometry,
            nr_meta_zones,
            nr_meta_blocks,
            nr_map_blocks,
            nr_bitmap_blocks,
            nr_chunks,
            nr_reserved_seq,
        })
    }

    /// The geometry this layout was computed for.
    #[must_use]
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// The number of data chunks the volume exposes.
    #[must_use]
    pub fn nr_chunks(&self) -> u32 {
        self.nr_chunks
    }

    /// The logical size dm-zoned presents, in 512-byte sectors: one chunk
    /// per zone. This is the length for the `zoned` table row.
    #[must_use]
    pub fn logical_sectors(&self) -> u64 {
        u64::from(self.nr_chunks)
            * u64::from(self.geometry.zone_size_blocks)
            * (BLOCK_SIZE as u64 / 512)
    }

    /// Blocks in one metadata set.
    #[must_use]
    pub fn nr_meta_blocks(&self) -> u32 {
        self.nr_meta_blocks
    }

    /// The absolute block where metadata `set` begins — 0 for the primary,
    /// `nr_meta_zones` zones later for the secondary mirror. Passing a set
    /// other than 0 or 1 is meaningless (there are only two).
    #[must_use]
    pub fn set_start_block(&self, set: u32) -> u64 {
        u64::from(set) * u64::from(self.nr_meta_zones) * u64::from(self.geometry.zone_size_blocks)
    }

    /// Assemble one metadata set's `nr_meta_blocks` contiguous blocks: the
    /// superblock, then the all-unmapped chunk mapping table, then the
    /// zeroed bitmap region. Write the result at
    /// `set_start_block(set) * BLOCK_SIZE`.
    #[must_use]
    pub fn metadata_set(&self, set: u32, options: &FormatOptions) -> Vec<u8> {
        let mut region = vec![0u8; self.nr_meta_blocks as usize * BLOCK_SIZE];

        let sb = Superblock {
            version: FORMAT_VERSION,
            generation: 1,
            sb_block: self.set_start_block(set),
            nr_meta_blocks: self.nr_meta_blocks,
            nr_reserved_seq: self.nr_reserved_seq,
            nr_chunks: self.nr_chunks,
            nr_map_blocks: self.nr_map_blocks,
            nr_bitmap_blocks: self.nr_bitmap_blocks,
            label: options.label,
            dmz_uuid: options.dmz_uuid,
            dev_uuid: options.dev_uuid,
        };
        region[..BLOCK_SIZE].copy_from_slice(&sb.to_block());

        // Mapping table: every entry DMZ_MAP_UNMAPPED. Both ids are
        // 0xFFFFFFFF, so the whole region is 0xFF bytes.
        let map_start = BLOCK_SIZE;
        let map_end = map_start + self.nr_map_blocks as usize * BLOCK_SIZE;
        debug_assert_eq!(MAP_UNMAPPED, u32::MAX);
        region[map_start..map_end].fill(0xff);

        // Bitmap region stays zero: a fresh volume has no valid blocks.
        region
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The geometry of the null_blk device the superblock fixture came
    /// from: 256 MiB, 4 MiB zones (1024 blocks), 8 conventional zones.
    const FIXTURE_GEOMETRY: Geometry = Geometry {
        total_zones: 64,
        zone_size_blocks: 1024,
        conventional_zones: 8,
    };

    #[test]
    fn compute_reproduces_the_dmzadm_counts() {
        let layout = Layout::compute(FIXTURE_GEOMETRY, &FormatOptions::default()).unwrap();
        // These are exactly what dmzadm wrote (checked in the superblock
        // fixture test): 64 - 2 meta - 7 reserved = 55 chunks.
        assert_eq!(layout.nr_reserved_seq, 7);
        assert_eq!(layout.nr_chunks, 55);
        assert_eq!(layout.nr_map_blocks, 1);
        assert_eq!(layout.nr_bitmap_blocks, 64);
        assert_eq!(layout.nr_meta_blocks, 66);
        assert_eq!(layout.nr_meta_zones, 1);
    }

    #[test]
    fn secondary_set_starts_a_metadata_zone_later() {
        let layout = Layout::compute(FIXTURE_GEOMETRY, &FormatOptions::default()).unwrap();
        assert_eq!(layout.set_start_block(0), 0);
        // One metadata zone of 1024 blocks in.
        assert_eq!(layout.set_start_block(1), 1024);
    }

    #[test]
    fn metadata_set_has_a_valid_superblock_map_and_bitmap() {
        let layout = Layout::compute(FIXTURE_GEOMETRY, &FormatOptions::default()).unwrap();
        let region = layout.metadata_set(0, &FormatOptions::default());
        assert_eq!(region.len(), 66 * BLOCK_SIZE);

        // Block 0 is a superblock the reader accepts, echoing the counts.
        let block: [u8; BLOCK_SIZE] = region[..BLOCK_SIZE].try_into().unwrap();
        let sb = Superblock::from_block(&block).expect("valid superblock");
        assert_eq!(sb.nr_chunks, 55);
        assert_eq!(sb.sb_block, 0);

        // Block 1 is the mapping table: every chunk unmapped (all 0xFF).
        assert!(
            region[BLOCK_SIZE..2 * BLOCK_SIZE]
                .iter()
                .all(|&b| b == 0xff)
        );

        // The bitmap region (blocks 2..66) is zeroed.
        assert!(region[2 * BLOCK_SIZE..].iter().all(|&b| b == 0));
    }

    #[test]
    fn secondary_superblock_records_its_own_block() {
        let layout = Layout::compute(FIXTURE_GEOMETRY, &FormatOptions::default()).unwrap();
        let region = layout.metadata_set(1, &FormatOptions::default());
        let block: [u8; BLOCK_SIZE] = region[..BLOCK_SIZE].try_into().unwrap();
        let sb = Superblock::from_block(&block).expect("valid secondary superblock");
        assert_eq!(sb.sb_block, 1024, "the mirror knows where it lives");
    }

    #[test]
    fn a_purely_sequential_device_is_rejected() {
        let geometry = Geometry {
            conventional_zones: 0,
            ..FIXTURE_GEOMETRY
        };
        assert_eq!(
            Layout::compute(geometry, &FormatOptions::default()),
            Err(LayoutError::NotEnoughConventionalZones { have: 0, need: 2 })
        );
    }

    #[test]
    fn a_tiny_device_has_no_data_zones() {
        let geometry = Geometry {
            total_zones: 2,
            zone_size_blocks: 1024,
            conventional_zones: 2,
        };
        // reserved_seq defaults to at least 1, and two metadata sets need
        // two zones, so two total zones leave nothing.
        assert_eq!(
            Layout::compute(geometry, &FormatOptions::default()),
            Err(LayoutError::NoDataZones)
        );
    }
}
