// SPDX-License-Identifier: Apache-2.0

//! `dm-array`: a dense, indexed sequence of fixed-size values.
//!
//! Where a btree maps sparse `u64` keys to values, an array addresses
//! *every* index from zero. dm-cache and dm-era both need that — a cache
//! has a value for each of its cache blocks, an era array a value for each
//! origin block — and a btree would waste a key per entry storing indices
//! that are implied by position.
//!
//! The implementation is a btree of **array blocks**: the btree maps a
//! block index to the metadata block holding that slice of the array, and
//! each array block packs values back to back after a short header.
//!
//! # A header that is not like the others
//!
//! Every other structure here puts `blocknr` immediately after `csum`.
//! An array block does not — its header is `csum, max_entries, nr_entries,
//! value_size, blocknr`, so the address lands at offset 16. Reading it from
//! the usual offset 8 would silently compare against `max_entries`, so this
//! module validates through [`read_validated_at`](crate::block::read_validated_at).

use crate::block::{BLOCK_SIZE, Blocks, le32, read_validated_at};
use crate::btree::ValueSize;
use crate::{ARRAY_CSUM_XOR, Error, btree};

/// Byte size of an `array_block` header.
pub const HEADER_SIZE: usize = 24;
/// Offset of an array block's self-recorded address.
const OFF_BLOCKNR: usize = 16;
// Header field offsets.
const OFF_MAX_ENTRIES: usize = 4;
const OFF_NR_ENTRIES: usize = 8;
const OFF_VALUE_SIZE: usize = 12;
/// Depth bound for the index btree.
const MAX_DEPTH: usize = 16;
/// The index btree's values are array-block numbers, so `u64`.
const INDEX_VALUE_SIZE: ValueSize = ValueSize(8);

/// Values one array block holds, for a given value size.
#[must_use]
pub fn max_entries(value_size: usize) -> usize {
    if value_size == 0 {
        return 0;
    }
    (BLOCK_SIZE - HEADER_SIZE) / value_size
}

/// One array block: a run of values from the array.
#[derive(Debug)]
pub struct ArrayBlock {
    /// The block it was read from.
    pub block: u64,
    /// Bytes per value.
    pub value_size: usize,
    /// Values actually present.
    pub nr_entries: usize,
    raw: Vec<u8>,
}

impl ArrayBlock {
    /// Read and validate the array block at `block`.
    ///
    /// # Errors
    ///
    /// A checksum or location error, or [`Error::Malformed`] if the header
    /// describes more values than the block can hold.
    pub fn read<B: Blocks + ?Sized>(blocks: &B, block: u64) -> Result<Self, Error> {
        let raw = read_validated_at(blocks, block, ARRAY_CSUM_XOR, OFF_BLOCKNR)?;
        let max = le32(&raw, OFF_MAX_ENTRIES) as usize;
        let nr_entries = le32(&raw, OFF_NR_ENTRIES) as usize;
        let value_size = le32(&raw, OFF_VALUE_SIZE) as usize;

        let malformed = |reason: String| Error::Malformed { block, reason };
        if value_size == 0 {
            return Err(malformed("array block has a zero value size".to_owned()));
        }
        if nr_entries > max || max > max_entries(value_size) {
            return Err(malformed(format!(
                "{nr_entries} of {max} entries of {value_size} bytes do not fit a block"
            )));
        }
        Ok(ArrayBlock {
            block,
            value_size,
            nr_entries,
            raw,
        })
    }

    /// Check this block's values are the width the caller expects.
    ///
    /// An array block declares its own `value_size`, and nothing ties that
    /// to what the array is an array *of*, so a caller decoding at a fixed
    /// width states that width here rather than length-checking each value.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the block declares some other width.
    pub fn check_values(&self, expect: ValueSize) -> Result<(), Error> {
        if self.value_size != expect.0 {
            return Err(Error::Malformed {
                block: self.block,
                reason: format!(
                    "array block has {}-byte values, expected {}",
                    self.value_size, expect.0
                ),
            });
        }
        Ok(())
    }

    /// The value at `index` within this block.
    #[must_use]
    pub fn value(&self, index: usize) -> Option<&[u8]> {
        if index >= self.nr_entries {
            return None;
        }
        let start = HEADER_SIZE + index * self.value_size;
        self.raw.get(start..start + self.value_size)
    }
}

/// Visit every value of the array rooted at `root`, in index order,
/// calling `visit(index, value)`.
///
/// Every value handed to `visit` is exactly `expect` bytes long; an array
/// block declaring any other width is rejected before its values are read.
///
/// # Errors
///
/// The first structural error encountered, or whatever `visit` returns.
pub fn walk<B, F>(blocks: &B, root: u64, expect: ValueSize, visit: &mut F) -> Result<(), Error>
where
    B: Blocks + ?Sized,
    F: FnMut(u64, &[u8]) -> Result<(), Error>,
{
    // The index btree maps array-block number to the block holding it, so
    // walking it in key order walks the array in index order.
    let mut index = 0u64;
    btree::walk(
        blocks,
        root,
        MAX_DEPTH,
        INDEX_VALUE_SIZE,
        &mut |_key, value| {
            let block = crate::block::le64(value, 0);
            let ab = ArrayBlock::read(blocks, block)?;
            ab.check_values(expect)?;
            for i in 0..ab.nr_entries {
                let value = ab.value(i).ok_or_else(|| Error::Malformed {
                    block,
                    reason: format!("value {i} runs past the block"),
                })?;
                visit(index, value)?;
                index += 1;
            }
            Ok(())
        },
    )
}

/// Collect every value of the array rooted at `root`.
///
/// # Errors
///
/// As [`walk`].
pub fn collect<B: Blocks + ?Sized>(
    blocks: &B,
    root: u64,
    expect: ValueSize,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    walk(blocks, root, expect, &mut |_index, value| {
        out.push(value.to_vec());
        Ok(())
    })?;
    Ok(out)
}

/// Every metadata block the array occupies: its index btree and its array
/// blocks.
///
/// Needed by a reference-count audit, which must account for both.
///
/// # Errors
///
/// A structural error from the index btree.
pub fn blocks_used<B: Blocks + ?Sized>(blocks: &B, root: u64) -> Result<Vec<u64>, Error> {
    let mut used = Vec::new();
    btree::walk_nodes(blocks, root, MAX_DEPTH, &mut |node| {
        used.push(node.block);
        Ok(())
    })?;
    for (_, value) in btree::collect(blocks, root, MAX_DEPTH, INDEX_VALUE_SIZE)? {
        used.push(crate::block::le64(&value, 0));
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    /// Build an array block holding `values`.
    fn array_block(block: u64, value_size: usize, values: &[Vec<u8>]) -> Vec<u8> {
        let mut raw = vec![0u8; BLOCK_SIZE];
        let max = max_entries(value_size);
        raw[OFF_MAX_ENTRIES..OFF_MAX_ENTRIES + 4]
            .copy_from_slice(&u32::try_from(max).expect("fits").to_le_bytes());
        raw[OFF_NR_ENTRIES..OFF_NR_ENTRIES + 4]
            .copy_from_slice(&u32::try_from(values.len()).expect("fits").to_le_bytes());
        raw[OFF_VALUE_SIZE..OFF_VALUE_SIZE + 4]
            .copy_from_slice(&u32::try_from(value_size).expect("fits").to_le_bytes());
        raw[OFF_BLOCKNR..OFF_BLOCKNR + 8].copy_from_slice(&block.to_le_bytes());
        for (i, value) in values.iter().enumerate() {
            let at = HEADER_SIZE + i * value_size;
            raw[at..at + value_size].copy_from_slice(value);
        }
        let csum = checksum(&raw, ARRAY_CSUM_XOR);
        raw[0..4].copy_from_slice(&csum.to_le_bytes());
        raw
    }

    #[test]
    fn capacity_leaves_room_for_the_header() {
        assert_eq!(max_entries(8), (BLOCK_SIZE - HEADER_SIZE) / 8);
        assert_eq!(max_entries(4), (BLOCK_SIZE - HEADER_SIZE) / 4);
        assert_eq!(max_entries(0), 0, "a zero value size holds nothing");
    }

    #[test]
    fn reads_values_out_of_an_array_block() {
        let values: Vec<Vec<u8>> = (0..3u64).map(|i| i.to_le_bytes().to_vec()).collect();
        let image = array_block(0, 8, &values);
        let ab = ArrayBlock::read(image.as_slice(), 0).expect("read");
        assert_eq!(ab.nr_entries, 3);
        assert_eq!(ab.value(1).expect("value"), &1u64.to_le_bytes());
        assert!(ab.value(3).is_none(), "past the end");
    }

    #[test]
    fn validates_the_address_at_offset_sixteen() {
        // An array block orders its header differently from every other
        // structure; reading blocknr from the usual offset 8 would compare
        // against max_entries and accept a misplaced block.
        let values = vec![7u64.to_le_bytes().to_vec()];
        let image = array_block(5, 8, &values);
        // Found at block 0 but built for block 5.
        assert!(matches!(
            ArrayBlock::read(image.as_slice(), 0),
            Err(Error::WrongLocation {
                block: 0,
                claimed: 5
            })
        ));
    }

    #[test]
    fn rejects_a_header_that_overflows_the_block() {
        let mut image = array_block(0, 8, &[1u64.to_le_bytes().to_vec()]);
        image[OFF_MAX_ENTRIES..OFF_MAX_ENTRIES + 4].copy_from_slice(&100_000u32.to_le_bytes());
        let csum = checksum(&image, ARRAY_CSUM_XOR);
        image[0..4].copy_from_slice(&csum.to_le_bytes());
        assert!(matches!(
            ArrayBlock::read(image.as_slice(), 0),
            Err(Error::Malformed { .. })
        ));
    }

    /// A one-block array: an index btree at block 0 whose single value
    /// points at the array block in block 1.
    fn array_image(value_size: usize, values: &[Vec<u8>]) -> Vec<u8> {
        let mut image = vec![0u8; BLOCK_SIZE * 2];
        let index = btree::node_block(0, true, 8, &[(0, 1u64.to_le_bytes().to_vec())]);
        image[..BLOCK_SIZE].copy_from_slice(&index);
        image[BLOCK_SIZE..].copy_from_slice(&array_block(1, value_size, values));
        image
    }

    #[test]
    fn walks_an_array_of_the_expected_width() {
        let values: Vec<Vec<u8>> = (0..3u64).map(|i| i.to_le_bytes().to_vec()).collect();
        let image = array_image(8, &values);
        let got = collect(image.as_slice(), 0, ValueSize(8)).expect("walk");
        assert_eq!(got, values);
    }

    #[test]
    fn rejects_an_array_block_of_the_wrong_width() {
        // The block declares 4-byte values; a caller decoding a u64 out of
        // one would index past its end. That must be reported, not
        // panicked — dumping corrupt metadata is the whole use case.
        let values: Vec<Vec<u8>> = (0..3u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let image = array_image(4, &values);
        assert!(matches!(
            collect(image.as_slice(), 0, ValueSize(8)),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_a_zero_value_size() {
        // Would otherwise divide by zero when locating values.
        let mut image = array_block(0, 8, &[1u64.to_le_bytes().to_vec()]);
        image[OFF_VALUE_SIZE..OFF_VALUE_SIZE + 4].copy_from_slice(&0u32.to_le_bytes());
        let csum = checksum(&image, ARRAY_CSUM_XOR);
        image[0..4].copy_from_slice(&csum.to_le_bytes());
        assert!(matches!(
            ArrayBlock::read(image.as_slice(), 0),
            Err(Error::Malformed { .. })
        ));
    }
}
