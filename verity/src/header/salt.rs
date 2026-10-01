// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

const MAX_SIZE: usize = 256;

/// Salt bytes recorded in a dm-verity header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Salt([u8; MAX_SIZE], usize);

impl Salt {
    /// Constructs a salt when the bytes fit in the on-disk header.
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
