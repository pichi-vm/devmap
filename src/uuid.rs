// SPDX-License-Identifier: Apache-2.0

//! Parse and render the 16-byte UUIDs the verity and zoned formats carry.
//! Cosmetic identity, not a security boundary — the personas default them
//! to random bytes and let callers override.

use anyhow::{Result, anyhow};

use crate::hex;

/// Format a 16-byte UUID in canonical 8-4-4-4-12 hyphenated form.
pub(crate) fn format(uuid: &[u8; 16]) -> String {
    let h = hex::encode(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Parse a UUID given as 32 hex chars or the canonical hyphenated form.
///
/// # Errors
///
/// Fails if the string isn't 16 bytes of hex once hyphens are stripped.
pub(crate) fn parse(s: &str) -> Result<[u8; 16]> {
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(&stripped)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("uuid must be 16 bytes (32 hex digits)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_forms() {
        let raw = [
            0x3b, 0x4c, 0x08, 0xd6, 0x64, 0x33, 0xc6, 0x2f, 0x91, 0xc6, 0xb3, 0xe2, 0x93, 0x43,
            0xb6, 0xc1,
        ];
        let canonical = "3b4c08d6-6433-c62f-91c6-b3e29343b6c1";
        assert_eq!(format(&raw), canonical);
        assert_eq!(parse(canonical).unwrap(), raw);
        // The un-hyphenated form parses to the same bytes.
        assert_eq!(parse(&hex::encode(&raw)).unwrap(), raw);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse("abcd").is_err());
    }
}
