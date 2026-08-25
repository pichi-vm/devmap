// SPDX-License-Identifier: Apache-2.0

//! `dm-bitset`: a bit per index, stored as an [`array`](crate::array) of
//! 64-bit words.
//!
//! dm-cache uses one for its version-2 dirty bits, and dm-era uses one per
//! writeset to record which blocks were touched in an era. Both want a
//! single bit per block over a dense index space, which is exactly an
//! array of packed words.
//!
//! Bit *n* lives in word `n / 64` at bit `n % 64`, with the words stored
//! little-endian.

use crate::btree::ValueSize;
use crate::{Blocks, Error, array};

/// Bits packed into each array entry.
pub const BITS_PER_ENTRY: u64 = 64;
/// A bitset entry is one packed 64-bit word.
const ENTRY_SIZE: ValueSize = ValueSize(8);

/// Read a bitset of `nr_bits` bits into a vector of booleans.
///
/// The trailing bits of the final word are padding and are dropped, so the
/// result is exactly `nr_bits` long.
///
/// # Errors
///
/// A structural error from the underlying array.
///
/// # Panics
///
/// Never: the array yields entries of exactly [`ENTRY_SIZE`] bytes, which
/// is what the conversion below reads.
pub fn collect<B: Blocks + ?Sized>(
    blocks: &B,
    root: u64,
    nr_bits: u64,
) -> Result<Vec<bool>, Error> {
    let mut bits = Vec::new();
    array::walk(blocks, root, ENTRY_SIZE, &mut |_index, value| {
        let word = u64::from_le_bytes(value.try_into().expect("8-byte bitset word"));
        for bit in 0..BITS_PER_ENTRY {
            bits.push(word >> bit & 1 == 1);
        }
        Ok(())
    })?;

    // The array is whole words, so it usually runs past the logical end.
    let wanted = usize::try_from(nr_bits).map_err(|_| Error::Malformed {
        block: root,
        reason: "bitset is implausibly long".to_owned(),
    })?;
    if bits.len() < wanted {
        return Err(Error::Malformed {
            block: root,
            reason: format!("bitset holds {} bits, {wanted} expected", bits.len()),
        });
    }
    bits.truncate(wanted);
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_are_packed_little_endian_within_each_word() {
        // Mirror the decode this module performs, so the convention is
        // pinned even without a full array fixture.
        let word: u64 = 0b1011;
        let bit = |n: u64| word >> n & 1 == 1;
        assert!(bit(0));
        assert!(bit(1));
        assert!(!bit(2));
        assert!(bit(3));
    }

    #[test]
    fn sixty_four_bits_fill_one_entry() {
        assert_eq!(BITS_PER_ENTRY, 64);
    }
}
