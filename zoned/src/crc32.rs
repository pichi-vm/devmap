// SPDX-License-Identifier: Apache-2.0

//! The kernel's `crc32_le`, which dm-zoned seeds with the superblock
//! generation number.
//!
//! This is *not* the standard zlib/IEEE CRC-32: the kernel's `crc32_le`
//! applies no pre-inversion of the seed and no post-inversion of the
//! result — it is the bare reflected-polynomial LFSR. The common Rust
//! crates (`crc32fast`, `crc`'s `CRC_32_ISO_HDLC`) all do the zlib
//! conditioning, so none of them reproduces the value dm-zoned stores.
//! Hence this small dedicated implementation.

/// The reflected form of the IEEE 802.3 polynomial, as the kernel uses.
const POLY: u32 = 0xEDB8_8320;

/// `crc32_le(seed, data)` — the kernel function of the same name.
///
/// `seed` is the running CRC to continue from; dm-zoned passes the
/// superblock generation number (1 for a freshly formatted device). No
/// inversion is applied to either the seed or the result.
#[must_use]
pub fn crc32_le(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            // Branchless reduce: subtract the polynomial when the low bit
            // is set, matching the kernel's bit-at-a-time reference.
            crc = (crc >> 1) ^ (POLY & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_crc32_check_value_under_zlib_conditioning() {
        // The universal CRC-32/ISO-HDLC check value is 0xCBF43926 for
        // "123456789". That variant is the bare LFSR with the seed and
        // result inverted, so applying exactly that conditioning to this
        // raw crc32_le must reproduce it — an independent check against a
        // constant that isn't derived from this implementation.
        assert_eq!(crc32_le(!0, b"123456789") ^ !0, 0xCBF4_3926);
    }

    #[test]
    fn seed_continues_a_running_crc() {
        // Feeding two halves with the first result as the second seed
        // equals hashing the whole — the property dm-zoned relies on when
        // it seeds with the generation number.
        let whole = crc32_le(0, b"123456789");
        let split = crc32_le(crc32_le(0, b"12345"), b"6789");
        assert_eq!(whole, split);
    }
}
