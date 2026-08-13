// SPDX-License-Identifier: Apache-2.0

//! The persistent-data btree: `u64` keys to fixed-size values.
//!
//! One node per metadata block. A node is a header, then a sorted array of
//! `max_entries` keys, then the values packed after them. Internal nodes
//! carry `u64` child block numbers as their values; leaf nodes carry
//! whatever the tree is a tree *of* — a data-block mapping, a device's
//! details, a space-map index entry.
//!
//! Keys are sorted within a node and across siblings, so a walk in node
//! order is a walk in key order. This reader checks that ordering rather
//! than trusting it: an out-of-order key means corruption, and silently
//! accepting it would produce a plausible-looking but wrong dump.

use crate::block::{BLOCK_SIZE, Blocks, le32, le64, read_validated};
use crate::{BTREE_CSUM_XOR, Error};

/// Byte size of a node header.
const HEADER_SIZE: usize = 32;
// Header field offsets.
const OFF_FLAGS: usize = 4;
const OFF_NR_ENTRIES: usize = 16;
const OFF_MAX_ENTRIES: usize = 20;
const OFF_VALUE_SIZE: usize = 24;

/// `INTERNAL_NODE` — values are child block numbers.
const INTERNAL_NODE: u32 = 1;
/// `LEAF_NODE` — values are the tree's payload.
const LEAF_NODE: u32 = 1 << 1;

/// One btree node, borrowed from its block.
#[derive(Debug)]
pub struct Node {
    /// The block this node was read from.
    pub block: u64,
    /// Whether this is a leaf (values are payload) or internal (children).
    pub leaf: bool,
    /// Keys present, in ascending order.
    pub keys: Vec<u64>,
    /// The raw block, so values can be sliced out.
    raw: Vec<u8>,
    /// Bytes per value.
    value_size: usize,
    /// Where the value array begins.
    values_at: usize,
}

impl Node {
    /// Parse and validate the node in `raw`, which came from `block`.
    ///
    /// Enforces the same bounds the kernel does — the key and value arrays
    /// must fit the block — plus ascending key order.
    fn parse(block: u64, raw: Vec<u8>) -> Result<Self, Error> {
        let malformed = |reason: String| Error::Malformed { block, reason };

        let flags = le32(&raw, OFF_FLAGS);
        let leaf = match flags {
            f if f == LEAF_NODE => true,
            f if f == INTERNAL_NODE => false,
            other => return Err(malformed(format!("unknown node flags {other:#x}"))),
        };

        let nr_entries = le32(&raw, OFF_NR_ENTRIES) as usize;
        let max_entries = le32(&raw, OFF_MAX_ENTRIES) as usize;
        let value_size = le32(&raw, OFF_VALUE_SIZE) as usize;

        if nr_entries > max_entries {
            return Err(malformed(format!(
                "{nr_entries} entries in a node sized for {max_entries}"
            )));
        }
        // The kernel's own bound: `(8 + value_size) * max_entries` must not
        // exceed the block size.
        if value_size == 0
            || max_entries
                .checked_mul(8 + value_size)
                .is_none_or(|need| need > BLOCK_SIZE)
        {
            return Err(malformed(format!(
                "{max_entries} entries of {value_size}-byte values do not fit a block"
            )));
        }
        // An internal node's values are child pointers, so must be u64.
        if !leaf && value_size != 8 {
            return Err(malformed(format!(
                "internal node has {value_size}-byte values, expected 8"
            )));
        }

        let keys: Vec<u64> = (0..nr_entries)
            .map(|i| le64(&raw, HEADER_SIZE + i * 8))
            .collect();
        if keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err(malformed("keys are not in ascending order".to_owned()));
        }

        Ok(Node {
            block,
            leaf,
            keys,
            values_at: HEADER_SIZE + max_entries * 8,
            value_size,
            raw,
        })
    }

    /// The raw bytes of the value at `index`.
    #[must_use]
    pub fn value(&self, index: usize) -> Option<&[u8]> {
        if index >= self.keys.len() {
            return None;
        }
        let start = self.values_at + index * self.value_size;
        self.raw.get(start..start + self.value_size)
    }

    /// The child block number at `index`, for an internal node.
    ///
    /// # Panics
    ///
    /// Never: an internal node is rejected at parse time unless its values
    /// are exactly 8 bytes.
    #[must_use]
    pub fn child(&self, index: usize) -> Option<u64> {
        if self.leaf {
            return None;
        }
        self.value(index)
            .map(|v| u64::from_le_bytes(v.try_into().expect("8-byte child pointer")))
    }

    /// Bytes per value in this node.
    #[must_use]
    pub fn value_size(&self) -> usize {
        self.value_size
    }
}

/// Read and validate the btree node at `block`.
///
/// # Errors
///
/// A checksum, location, or structural error.
pub fn read_node<B: Blocks + ?Sized>(blocks: &B, block: u64) -> Result<Node, Error> {
    let raw = read_validated(blocks, block, BTREE_CSUM_XOR)?;
    Node::parse(block, raw)
}

/// Walk every leaf entry of the tree rooted at `root`, in key order,
/// calling `visit(key, value)`.
///
/// Depth is bounded by `max_depth` so a corrupt tree with a cycle or an
/// absurd height cannot loop forever — an unbounded walk over attacker- or
/// corruption-controlled pointers would hang instead of reporting.
///
/// # Errors
///
/// The first structural error encountered, or whatever `visit` returns.
pub fn walk<B, F>(blocks: &B, root: u64, max_depth: usize, visit: &mut F) -> Result<(), Error>
where
    B: Blocks + ?Sized,
    F: FnMut(u64, &[u8]) -> Result<(), Error>,
{
    if max_depth == 0 {
        return Err(Error::Malformed {
            block: root,
            reason: "btree is deeper than expected (possible cycle)".to_owned(),
        });
    }
    let node = read_node(blocks, root)?;
    for index in 0..node.keys.len() {
        if node.leaf {
            let value = node.value(index).ok_or_else(|| Error::Malformed {
                block: root,
                reason: format!("value {index} runs past the block"),
            })?;
            visit(node.keys[index], value)?;
        } else {
            let child = node.child(index).ok_or_else(|| Error::Malformed {
                block: root,
                reason: format!("child pointer {index} runs past the block"),
            })?;
            walk(blocks, child, max_depth - 1, visit)?;
        }
    }
    Ok(())
}

/// Collect every `(key, value)` of the tree rooted at `root`.
///
/// Convenience over [`walk`] for trees small enough to hold in memory,
/// which the device-details and space-map index trees always are.
///
/// # Errors
///
/// As [`walk`].
pub fn collect<B: Blocks + ?Sized>(
    blocks: &B,
    root: u64,
    max_depth: usize,
) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    let mut out = Vec::new();
    walk(blocks, root, max_depth, &mut |key, value| {
        out.push((key, value.to_vec()));
        Ok(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    /// Build a btree node block.
    fn node_block(
        block: u64,
        leaf: bool,
        value_size: usize,
        entries: &[(u64, Vec<u8>)],
    ) -> Vec<u8> {
        let mut raw = vec![0u8; BLOCK_SIZE];
        let max_entries = (BLOCK_SIZE - HEADER_SIZE) / (8 + value_size);
        raw[OFF_FLAGS..OFF_FLAGS + 4]
            .copy_from_slice(&(if leaf { LEAF_NODE } else { INTERNAL_NODE }).to_le_bytes());
        raw[8..16].copy_from_slice(&block.to_le_bytes());
        raw[OFF_NR_ENTRIES..OFF_NR_ENTRIES + 4].copy_from_slice(
            &u32::try_from(entries.len())
                .expect("test entry count fits u32")
                .to_le_bytes(),
        );
        raw[OFF_MAX_ENTRIES..OFF_MAX_ENTRIES + 4]
            .copy_from_slice(&u32::try_from(max_entries).expect("fits u32").to_le_bytes());
        raw[OFF_VALUE_SIZE..OFF_VALUE_SIZE + 4]
            .copy_from_slice(&u32::try_from(value_size).expect("fits u32").to_le_bytes());
        let values_at = HEADER_SIZE + max_entries * 8;
        for (i, (key, value)) in entries.iter().enumerate() {
            raw[HEADER_SIZE + i * 8..HEADER_SIZE + i * 8 + 8].copy_from_slice(&key.to_le_bytes());
            let at = values_at + i * value_size;
            raw[at..at + value_size].copy_from_slice(value);
        }
        let csum = checksum(&raw, BTREE_CSUM_XOR);
        raw[0..4].copy_from_slice(&csum.to_le_bytes());
        raw
    }

    /// A one-leaf tree at block 0.
    fn single_leaf() -> Vec<u8> {
        node_block(
            0,
            true,
            8,
            &[
                (10, 100u64.to_le_bytes().to_vec()),
                (20, 200u64.to_le_bytes().to_vec()),
                (30, 300u64.to_le_bytes().to_vec()),
            ],
        )
    }

    #[test]
    fn walks_a_single_leaf_in_key_order() {
        let image = single_leaf();
        let got = collect(image.as_slice(), 0, 8).expect("walk");
        let keys: Vec<u64> = got.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, [10, 20, 30]);
        assert_eq!(
            u64::from_le_bytes(got[1].1.clone().try_into().unwrap()),
            200
        );
    }

    #[test]
    fn walks_an_internal_node_into_its_children() {
        // Root at block 0 pointing at leaves in blocks 1 and 2.
        let mut image = vec![0u8; BLOCK_SIZE * 3];
        let leaf_a = node_block(1, true, 8, &[(1, 11u64.to_le_bytes().to_vec())]);
        let leaf_b = node_block(2, true, 8, &[(5, 55u64.to_le_bytes().to_vec())]);
        let root = node_block(
            0,
            false,
            8,
            &[
                (1, 1u64.to_le_bytes().to_vec()),
                (5, 2u64.to_le_bytes().to_vec()),
            ],
        );
        image[..BLOCK_SIZE].copy_from_slice(&root);
        image[BLOCK_SIZE..BLOCK_SIZE * 2].copy_from_slice(&leaf_a);
        image[BLOCK_SIZE * 2..].copy_from_slice(&leaf_b);

        let got = collect(image.as_slice(), 0, 8).expect("walk");
        let keys: Vec<u64> = got.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, [1, 5], "leaves visited in key order");
    }

    #[test]
    fn rejects_keys_out_of_order() {
        // Descending keys would still "work" if we trusted them, and would
        // yield a plausible but wrong dump.
        let image = node_block(
            0,
            true,
            8,
            &[
                (30, 1u64.to_le_bytes().to_vec()),
                (10, 2u64.to_le_bytes().to_vec()),
            ],
        );
        assert!(matches!(
            read_node(image.as_slice(), 0),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_a_node_whose_entries_cannot_fit() {
        let mut image = single_leaf();
        // Claim far more entries than a 4 KiB block can hold.
        image[OFF_MAX_ENTRIES..OFF_MAX_ENTRIES + 4].copy_from_slice(&100_000u32.to_le_bytes());
        let csum = checksum(&image, BTREE_CSUM_XOR);
        image[0..4].copy_from_slice(&csum.to_le_bytes());
        assert!(matches!(
            read_node(image.as_slice(), 0),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_unknown_node_flags() {
        let mut image = single_leaf();
        image[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&7u32.to_le_bytes());
        let csum = checksum(&image, BTREE_CSUM_XOR);
        image[0..4].copy_from_slice(&csum.to_le_bytes());
        assert!(matches!(
            read_node(image.as_slice(), 0),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn a_cycle_terminates_instead_of_hanging() {
        // An internal node pointing at itself: without a depth bound this
        // walk would never return.
        let image = node_block(0, false, 8, &[(1, 0u64.to_le_bytes().to_vec())]);
        assert!(matches!(
            collect(image.as_slice(), 0, 4),
            Err(Error::Malformed { .. })
        ));
    }
}
