// SPDX-License-Identifier: Apache-2.0

//! Lowercase-hex encode/decode for CLI arguments and output — root
//! hashes, salts, and UUIDs are all passed and printed as hex.

use anyhow::{Result, bail};

/// Encode `bytes` as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap());
    }
    s
}

/// Decode a hex string (any case) into bytes.
///
/// # Errors
///
/// Fails if the string has an odd length or contains a non-hex digit.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("hex string has an odd number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex digit in {:?}", &s[i..i + 2]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0x00, 0xff, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(encode(&bytes), "00ffdeadbeef");
        assert_eq!(decode("00ffdeadbeef").unwrap(), bytes);
        assert_eq!(decode("00FFDEADBEEF").unwrap(), bytes);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("abc").is_err(), "odd length");
        assert!(decode("zz").is_err(), "non-hex digit");
    }
}
