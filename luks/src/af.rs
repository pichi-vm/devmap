// SPDX-License-Identifier: Apache-2.0

//! LUKS anti-forensic (AF) splitting.
//!
//! A keyslot does not store the master key directly. It stores the key
//! inflated to `stripes` times its length, built so that **every** stripe
//! is needed to recover it: losing any part leaves no partial information.
//! That way, wiping a keyslot only has to destroy a little of the area for
//! the key to become unrecoverable, even on media that does not reliably
//! overwrite in place.
//!
//! The construction is a hash-diffused XOR chain: process each stripe into
//! a running block, diffusing after each, and XOR the final stripe to
//! recover the key.

use crate::Hash;

/// Diffuse `block` in place: hash it in digest-sized pieces, each piece
/// keyed by its big-endian index so identical pieces diffuse differently.
// The block is one key long (tens of bytes), so the piece counter is far
// inside u32 — and the format defines it as a big-endian u32 regardless.
#[allow(clippy::cast_possible_truncation)]
fn diffuse(block: &mut [u8], hash: Hash) {
    let digest_size = hash.digest_size();
    let full = block.len() / digest_size;
    let tail = block.len() % digest_size;

    for i in 0..full {
        let start = i * digest_size;
        let digest = hash.digest_with_counter(i as u32, &block[start..start + digest_size]);
        block[start..start + digest_size].copy_from_slice(&digest);
    }
    if tail > 0 {
        let start = full * digest_size;
        let digest = hash.digest_with_counter(full as u32, &block[start..]);
        block[start..].copy_from_slice(&digest[..tail]);
    }
}

/// Recover a `key_size`-byte key from its `stripes`-way AF expansion.
///
/// `split` must be exactly `key_size * stripes` bytes. Returns `None` if it
/// is not, which is the only way this can fail.
#[must_use]
pub fn merge(split: &[u8], key_size: usize, stripes: usize, hash: Hash) -> Option<Vec<u8>> {
    if key_size == 0 || stripes == 0 || split.len() != key_size * stripes {
        return None;
    }
    let mut block = vec![0u8; key_size];
    // All stripes but the last fold into the running block, diffusing each
    // time; the last is XORed in undiffused to give the key.
    for stripe in 0..stripes - 1 {
        let start = stripe * key_size;
        for (b, s) in block.iter_mut().zip(&split[start..start + key_size]) {
            *b ^= s;
        }
        diffuse(&mut block, hash);
    }
    let last = (stripes - 1) * key_size;
    for (b, s) in block.iter_mut().zip(&split[last..last + key_size]) {
        *b ^= s;
    }
    Some(block)
}

/// Expand `key` into its `stripes`-way AF representation, the inverse of
/// [`merge`]. `random` supplies the `key_size * (stripes - 1)` random bytes
/// the expansion is built from; it must be cryptographically random, since
/// it is what makes partial recovery impossible.
///
/// Returns `None` if `random` is the wrong length.
#[must_use]
pub fn split(key: &[u8], stripes: usize, hash: Hash, random: &[u8]) -> Option<Vec<u8>> {
    let key_size = key.len();
    if key_size == 0 || stripes == 0 || random.len() != key_size * (stripes - 1) {
        return None;
    }
    let mut out = vec![0u8; key_size * stripes];
    // The first stripes-1 stripes are the supplied random bytes; the last
    // is whatever makes `merge` reproduce the key.
    out[..random.len()].copy_from_slice(random);

    let mut block = vec![0u8; key_size];
    for stripe in 0..stripes - 1 {
        let start = stripe * key_size;
        for (b, s) in block.iter_mut().zip(&out[start..start + key_size]) {
            *b ^= s;
        }
        diffuse(&mut block, hash);
    }
    let last = (stripes - 1) * key_size;
    for (i, byte) in block.iter().enumerate() {
        out[last + i] = byte ^ key[i];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_then_merge_recovers_the_key() {
        for hash in [Hash::Sha1, Hash::Sha256, Hash::Sha512] {
            for stripes in [1usize, 2, 4, 4000] {
                let key: Vec<u8> = (0..64u32).map(|i| (i * 7 % 251) as u8).collect();
                let random: Vec<u8> = (0..key.len() * (stripes - 1))
                    .map(|i| u8::try_from(i % 253).expect("i % 253 fits a u8"))
                    .collect();
                let expanded = split(&key, stripes, hash, &random).expect("split");
                assert_eq!(expanded.len(), key.len() * stripes);
                let merged = merge(&expanded, key.len(), stripes, hash).expect("merge");
                assert_eq!(merged, key, "hash={hash:?} stripes={stripes}");
            }
        }
    }

    #[test]
    fn merge_needs_every_stripe() {
        // The whole point of AF: corrupting any single byte of any stripe
        // must destroy the key, not degrade it.
        let key = vec![0xA5u8; 32];
        let random: Vec<u8> = (0..32u32 * 3).map(|i| (i % 251) as u8).collect();
        let expanded = split(&key, 4, Hash::Sha256, &random).expect("split");
        for corrupt_at in [0usize, 31, 32, 95, 96, 127] {
            let mut damaged = expanded.clone();
            damaged[corrupt_at] ^= 0x01;
            let merged = merge(&damaged, 32, 4, Hash::Sha256).expect("merge");
            assert_ne!(merged, key, "flipping byte {corrupt_at} must lose the key");
        }
        // Sanity: undamaged still recovers.
        assert_eq!(merge(&expanded, 32, 4, Hash::Sha256).unwrap(), key);
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert!(merge(&[0u8; 10], 4, 4, Hash::Sha256).is_none());
        assert!(split(&[0u8; 4], 4, Hash::Sha256, &[0u8; 5]).is_none());
        assert!(merge(&[], 0, 4, Hash::Sha256).is_none());
    }
}
