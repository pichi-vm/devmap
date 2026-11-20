// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io, ops::Deref, str::FromStr};

const MAX_SIZE: usize = 256;

/// Salt bytes recorded in a dm-verity header.
///
/// Holds up to 256 bytes; the default is an empty salt. Borrowing as a byte
/// slice exposes only the supplied bytes, not the unused storage.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Salt([u8; MAX_SIZE], usize);

impl Salt {
    /// Constructs a salt when the bytes fit in the on-disk header.
    ///
    /// Returns `None` for more than 256 bytes. An empty slice is accepted.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_SIZE {
            return None;
        }

        let mut storage = [0; MAX_SIZE];
        storage[..bytes.len()].copy_from_slice(bytes);
        Some(Self(storage, bytes.len()))
    }
}

impl Default for Salt {
    fn default() -> Self {
        Self([0; MAX_SIZE], 0)
    }
}

impl fmt::Display for Salt {
    /// Formats the supplied bytes as lowercase hex, without a prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Salt {
    type Err = io::Error;

    /// Parses up to 256 bytes of hex, accepting either case and an empty salt.
    /// Prefixes, whitespace, odd lengths and non-hex characters are rejected.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        fn half(byte: u8) -> io::Result<u8> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'A'..=b'F' => Ok(byte - b'A' + 10),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid salt hex digit",
                )),
            }
        }

        if text.len() > 2 * MAX_SIZE || !text.len().is_multiple_of(2) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid salt hex length",
            ));
        }
        let mut salt = Self([0; MAX_SIZE], text.len() / 2);
        for (index, pair) in text.as_bytes().chunks(2).enumerate() {
            salt.0[index] = (half(pair[0])? << 4) | half(pair[1])?;
        }
        Ok(salt)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Salt").field(&self.as_ref()).finish()
    }
}

impl Deref for Salt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..self.1]
    }
}

impl AsRef<[u8]> for Salt {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::Salt;

    #[test]
    fn hex_round_trip_including_empty_and_maximum() {
        for bytes in [Vec::new(), vec![0, 1, 0xab, 0xff], (0..=255).collect()] {
            let salt = Salt::new(&bytes).unwrap();
            let text = salt.to_string();
            assert_eq!(text.len(), 2 * bytes.len());
            assert!(!text.bytes().any(|byte| byte.is_ascii_uppercase()));
            assert_eq!(text.parse::<Salt>().unwrap(), salt);
            assert_eq!(text.to_uppercase().parse::<Salt>().unwrap(), salt);
        }
        assert_eq!(
            Salt::new(&[0, 1, 0xab, 0xff]).unwrap().to_string(),
            "0001abff"
        );
    }

    #[test]
    fn rejects_invalid_hex_before_exceeding_storage() {
        for text in ["0", "0x12", " 12", "12 ", "gg", "é", "１２"] {
            assert_eq!(
                text.parse::<Salt>().unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        for length in [513, 514] {
            assert_eq!(
                "g".repeat(length).parse::<Salt>().unwrap_err().to_string(),
                "invalid salt hex length"
            );
        }
    }

    #[test]
    fn debug_shows_only_salt_bytes() {
        assert_eq!(format!("{:?}", Salt::default()), "Salt([])");
        assert_eq!(
            format!("{:?}", Salt::new(&[1, 0, 3]).unwrap()),
            "Salt([1, 0, 3])"
        );
    }
}
