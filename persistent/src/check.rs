// SPDX-License-Identifier: Apache-2.0

//! Validating thin metadata, including a full reference-count audit.
//!
//! Structural validation — checksums, self-addresses, node bounds, key
//! order — happens as a side effect of reading, because every accessor
//! checks as it goes. What this module adds is the part reading alone
//! cannot do: **recomputing** the reference counts by walking everything
//! reachable, and reconciling them against the counts the space maps
//! actually store.
//!
//! That reconciliation is the check that matters. The space maps are what
//! decide whether a block may be reused, so a count that is too low is a
//! future corruption — the allocator will hand out a block that is still
//! in use — while a count that is too high leaks space forever. Neither
//! shows up as a bad checksum, because every individual block is perfectly
//! well formed.
//!
//! Counts above one are expected and correct: copy-on-write means a
//! snapshot and its origin share subtrees, so the audit counts *references*
//! rather than distinct blocks.

use std::collections::HashMap;

use crate::space_map::{self, SpaceMap};
use crate::thin::{self, Superblock};
use crate::{Blocks, Error, btree};

/// Depth bound for every tree walked here.
const MAX_DEPTH: usize = 16;

/// What a check found.
#[derive(Debug, Default)]
pub struct Report {
    /// Problems found, in the order they were discovered.
    pub errors: Vec<String>,
    /// Metadata blocks reachable from the superblock.
    pub metadata_blocks_used: u64,
    /// Distinct data blocks referenced by some mapping.
    pub data_blocks_used: u64,
}

impl Report {
    /// Whether the metadata is free of problems.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Reference counts recomputed by walking the metadata.
struct Counts {
    /// Metadata blocks, indexed by block number. Dense, because the
    /// metadata device is bounded.
    metadata: Vec<u32>,
    /// Data blocks. Sparse, because a pool can address far more data
    /// blocks than are ever mapped, so a dense vector would be untenable.
    data: HashMap<u64, u32>,
}

impl Counts {
    fn new(metadata_blocks: u64) -> Result<Self, Error> {
        let len = usize::try_from(metadata_blocks).map_err(|_| Error::Malformed {
            block: 0,
            reason: "metadata device size is implausibly large".to_owned(),
        })?;
        Ok(Counts {
            metadata: vec![0; len],
            data: HashMap::new(),
        })
    }

    /// Record one more reference to metadata `block`.
    fn hit_metadata(&mut self, block: u64, errors: &mut Vec<String>) {
        match usize::try_from(block)
            .ok()
            .and_then(|b| self.metadata.get_mut(b))
        {
            Some(slot) => *slot += 1,
            None => errors.push(format!(
                "metadata block {block} is referenced but lies beyond the metadata device"
            )),
        }
    }

    /// Record one more reference to a data block.
    fn hit_data(&mut self, block: u64) {
        *self.data.entry(block).or_insert(0) += 1;
    }
}

/// Check the thin metadata in `blocks`.
///
/// Reads everything reachable from the superblock, recomputes reference
/// counts, and reconciles them with the stored space maps. Structural
/// faults are collected rather than returned as a hard error, so one bad
/// subtree does not hide the rest of the report.
///
/// # Errors
///
/// Only for faults that make checking impossible at all — an unreadable
/// superblock, or a metadata device size that cannot be represented.
pub fn check<B: Blocks + ?Sized>(blocks: &B) -> Result<Report, Error> {
    let mut report = Report::default();
    // A superblock that will not parse leaves nothing to check against.
    let superblock = Superblock::read(blocks)?;
    let mut counts = Counts::new(superblock.metadata_nr_blocks)?;

    // The superblock itself is referenced once.
    counts.hit_metadata(thin::SUPERBLOCK_BLOCK, &mut report.errors);

    count_trees(blocks, &superblock, &mut counts, &mut report);

    // Open the space maps and count the blocks they themselves occupy.
    match thin::space_maps(blocks, &superblock) {
        Ok((data_sm, metadata_sm)) => {
            count_space_map(
                blocks,
                &superblock.data_sm,
                &data_sm,
                &mut counts,
                &mut report,
                true,
            );
            count_space_map(
                blocks,
                &superblock.metadata_sm,
                &metadata_sm,
                &mut counts,
                &mut report,
                false,
            );
            reconcile(blocks, &data_sm, &metadata_sm, &counts, &mut report);
        }
        Err(e) => report.errors.push(format!("space maps: {e}")),
    }

    report.metadata_blocks_used = counts.metadata.iter().filter(|&&c| c > 0).count() as u64;
    report.data_blocks_used = counts.data.len() as u64;
    Ok(report)
}

/// Count the blocks the device-details and mapping trees occupy, and the
/// data blocks their mappings point at.
fn count_trees<B: Blocks + ?Sized>(
    blocks: &B,
    superblock: &Superblock,
    counts: &mut Counts,
    report: &mut Report,
) {
    let count_nodes = |root: u64, what: &str, counts: &mut Counts, report: &mut Report| {
        let mut hits = Vec::new();
        if let Err(e) = btree::walk_nodes(blocks, root, MAX_DEPTH, &mut |node| {
            hits.push(node.block);
            Ok(())
        }) {
            report.errors.push(format!("{what}: {e}"));
        }
        for block in hits {
            counts.hit_metadata(block, &mut report.errors);
        }
    };

    count_nodes(
        superblock.device_details_root,
        "device details tree",
        counts,
        report,
    );
    count_nodes(
        superblock.data_mapping_root,
        "mapping tree (top level)",
        counts,
        report,
    );

    // Each device's own mapping tree, plus the data blocks it maps.
    let devices = match btree::collect(blocks, superblock.data_mapping_root, MAX_DEPTH) {
        Ok(devices) => devices,
        Err(e) => {
            report.errors.push(format!("mapping tree (top level): {e}"));
            return;
        }
    };
    for (dev_id, value) in devices {
        let root = crate::block::le64(&value, 0);
        count_nodes(
            root,
            &format!("mapping tree (device {dev_id})"),
            counts,
            report,
        );

        match thin::mappings(blocks, superblock, dev_id) {
            Ok(mappings) => {
                for mapping in mappings {
                    counts.hit_data(mapping.data_block);
                }
            }
            Err(e) => report
                .errors
                .push(format!("mappings of device {dev_id}: {e}")),
        }
    }
}

/// Count the metadata blocks a space map occupies: its index, its bitmap
/// blocks, and its overflow btree.
fn count_space_map<B: Blocks + ?Sized>(
    blocks: &B,
    root: &space_map::Root,
    map: &SpaceMap,
    counts: &mut Counts,
    report: &mut Report,
    index_is_btree: bool,
) {
    if index_is_btree {
        let mut hits = Vec::new();
        if let Err(e) = btree::walk_nodes(blocks, root.bitmap_root, MAX_DEPTH, &mut |node| {
            hits.push(node.block);
            Ok(())
        }) {
            report.errors.push(format!("space map index: {e}"));
        }
        for block in hits {
            counts.hit_metadata(block, &mut report.errors);
        }
    } else {
        // An inline index is a single block.
        counts.hit_metadata(root.bitmap_root, &mut report.errors);
    }

    for entry in &map.index {
        counts.hit_metadata(entry.blocknr, &mut report.errors);
    }

    // The overflow btree exists even when empty; root zero means absent.
    if root.ref_count_root != 0 {
        let mut hits = Vec::new();
        if let Err(e) = btree::walk_nodes(blocks, root.ref_count_root, MAX_DEPTH, &mut |node| {
            hits.push(node.block);
            Ok(())
        }) {
            report.errors.push(format!("space map overflow tree: {e}"));
        }
        for block in hits {
            counts.hit_metadata(block, &mut report.errors);
        }
    }
}

/// Reconcile only the metadata space map, for targets that have no data
/// space map of their own — cache and era track their data elsewhere.
fn reconcile_metadata<B: Blocks + ?Sized>(
    blocks: &B,
    metadata_sm: &SpaceMap,
    counts: &Counts,
    report: &mut Report,
) {
    for (block, &expected) in counts.metadata.iter().enumerate() {
        let block = block as u64;
        if block >= metadata_sm.root.nr_blocks {
            break;
        }
        match metadata_sm.ref_count(blocks, block) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => report.errors.push(format!(
                "metadata block {block}: {expected} references found, space map says {actual}"
            )),
            Err(e) => report.errors.push(format!("metadata block {block}: {e}")),
        }
    }
}

/// Check dm-cache metadata, reconciling its metadata reference counts.
///
/// # Errors
///
/// Only when the superblock cannot be read, which leaves nothing to check.
pub fn check_cache<B: Blocks + ?Sized>(blocks: &B) -> Result<Report, Error> {
    let superblock = crate::cache::Superblock::read(blocks)?;
    let mut report = Report::default();
    let mut counts = Counts::new(superblock.metadata_sm.nr_blocks)?;
    counts.hit_metadata(0, &mut report.errors);

    // The mapping and hint arrays, and the dirty and discard bitsets, are
    // all arrays underneath, so one helper accounts for every one of them.
    for (root, what) in [
        (superblock.mapping_root, "mapping array"),
        (superblock.hint_root, "hint array"),
        (superblock.dirty_root, "dirty bitset"),
        (superblock.discard_root, "discard bitset"),
    ] {
        if root == 0 {
            continue;
        }
        match crate::array::blocks_used(blocks, root) {
            Ok(used) => {
                for block in used {
                    counts.hit_metadata(block, &mut report.errors);
                }
            }
            Err(e) => report.errors.push(format!("{what}: {e}")),
        }
    }

    match SpaceMap::open(blocks, superblock.metadata_sm, space_map::Index::Inline) {
        Ok(metadata_sm) => {
            count_space_map(
                blocks,
                &superblock.metadata_sm,
                &metadata_sm,
                &mut counts,
                &mut report,
                false,
            );
            reconcile_metadata(blocks, &metadata_sm, &counts, &mut report);
        }
        Err(e) => report.errors.push(format!("metadata space map: {e}")),
    }

    report.metadata_blocks_used = counts.metadata.iter().filter(|&&c| c > 0).count() as u64;
    Ok(report)
}

/// Check dm-era metadata, reconciling its metadata reference counts.
///
/// # Errors
///
/// Only when the superblock cannot be read.
pub fn check_era<B: Blocks + ?Sized>(blocks: &B) -> Result<Report, Error> {
    let superblock = crate::era::Superblock::read(blocks)?;
    let mut report = Report::default();
    let mut counts = Counts::new(superblock.metadata_sm.nr_blocks)?;
    counts.hit_metadata(0, &mut report.errors);

    // The era array is an array; the writeset tree is a btree whose values
    // each point at a writeset's own bitset.
    if superblock.era_array_root != 0 {
        match crate::array::blocks_used(blocks, superblock.era_array_root) {
            Ok(used) => {
                for block in used {
                    counts.hit_metadata(block, &mut report.errors);
                }
            }
            Err(e) => report.errors.push(format!("era array: {e}")),
        }
    }
    if superblock.writeset_tree_root != 0 {
        let mut hits = Vec::new();
        if let Err(e) = btree::walk_nodes(
            blocks,
            superblock.writeset_tree_root,
            MAX_DEPTH,
            &mut |node| {
                hits.push(node.block);
                Ok(())
            },
        ) {
            report.errors.push(format!("writeset tree: {e}"));
        }
        for block in hits {
            counts.hit_metadata(block, &mut report.errors);
        }
        match btree::collect(blocks, superblock.writeset_tree_root, MAX_DEPTH) {
            Ok(writesets) => {
                for (era, value) in writesets {
                    let root = crate::block::le64(&value, 4);
                    if root == 0 {
                        continue;
                    }
                    match crate::array::blocks_used(blocks, root) {
                        Ok(used) => {
                            for block in used {
                                counts.hit_metadata(block, &mut report.errors);
                            }
                        }
                        Err(e) => report.errors.push(format!("writeset for era {era}: {e}")),
                    }
                }
            }
            Err(e) => report.errors.push(format!("writeset tree: {e}")),
        }
    }
    if superblock.current_writeset_root != 0 {
        match crate::array::blocks_used(blocks, superblock.current_writeset_root) {
            Ok(used) => {
                for block in used {
                    counts.hit_metadata(block, &mut report.errors);
                }
            }
            Err(e) => report.errors.push(format!("current writeset: {e}")),
        }
    }

    match SpaceMap::open(blocks, superblock.metadata_sm, space_map::Index::Inline) {
        Ok(metadata_sm) => {
            count_space_map(
                blocks,
                &superblock.metadata_sm,
                &metadata_sm,
                &mut counts,
                &mut report,
                false,
            );
            reconcile_metadata(blocks, &metadata_sm, &counts, &mut report);
        }
        Err(e) => report.errors.push(format!("metadata space map: {e}")),
    }

    report.metadata_blocks_used = counts.metadata.iter().filter(|&&c| c > 0).count() as u64;
    Ok(report)
}

/// Compare recomputed counts against what the space maps store.
fn reconcile<B: Blocks + ?Sized>(
    blocks: &B,
    data_sm: &SpaceMap,
    metadata_sm: &SpaceMap,
    counts: &Counts,
    report: &mut Report,
) {
    // Data blocks: every block some mapping points at must be recorded as
    // referenced at least that many times.
    for (&block, &expected) in &counts.data {
        match data_sm.ref_count(blocks, block) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => report.errors.push(format!(
                "data block {block}: {expected} references found, space map says {actual}"
            )),
            Err(e) => report.errors.push(format!("data block {block}: {e}")),
        }
    }

    // Metadata blocks: reconcile in both directions, since a count that is
    // too high leaks space just as surely as one too low invites reuse of a
    // live block.
    for (block, &expected) in counts.metadata.iter().enumerate() {
        let block = block as u64;
        if block >= metadata_sm.root.nr_blocks {
            break;
        }
        let actual = match metadata_sm.ref_count(blocks, block) {
            Ok(actual) => actual,
            Err(e) => {
                report.errors.push(format!("metadata block {block}: {e}"));
                continue;
            }
        };
        if actual != expected {
            report.errors.push(format!(
                "metadata block {block}: {expected} references found, space map says {actual}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_with_no_errors_is_clean() {
        let report = Report::default();
        assert!(report.is_clean());
    }

    #[test]
    fn a_report_with_errors_is_not_clean() {
        let report = Report {
            errors: vec!["something".to_owned()],
            ..Report::default()
        };
        assert!(!report.is_clean());
    }

    #[test]
    fn counts_flag_a_reference_beyond_the_device() {
        // A pointer past the end of the metadata device is corruption, not
        // a silently ignorable count.
        let mut counts = Counts::new(4).expect("counts");
        let mut errors = Vec::new();
        counts.hit_metadata(2, &mut errors);
        assert_eq!(errors.len(), 0, "{errors:?}");
        counts.hit_metadata(99, &mut errors);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(counts.metadata[2], 1);
    }

    #[test]
    fn counts_accumulate_shared_references() {
        // Copy-on-write sharing means the same block is legitimately
        // referenced more than once.
        let mut counts = Counts::new(4).expect("counts");
        let mut errors = Vec::new();
        counts.hit_metadata(1, &mut errors);
        counts.hit_metadata(1, &mut errors);
        assert_eq!(counts.metadata[1], 2);
        counts.hit_data(7);
        counts.hit_data(7);
        counts.hit_data(9);
        assert_eq!(counts.data[&7], 2);
        assert_eq!(counts.data[&9], 1);
    }
}
