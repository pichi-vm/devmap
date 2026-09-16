// SPDX-License-Identifier: Apache-2.0

use std::{fmt, io};

/// A borrowed, nonempty kernel signature-key description without NUL bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyDescription<'a>(&'a str);

impl<'a> TryFrom<&'a str> for KeyDescription<'a> {
    type Error = io::Error;
    fn try_from(value: &'a str) -> io::Result<Self> {
        if value.is_empty() || value.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid signature key description",
            ));
        }
        Ok(Self(value))
    }
}

impl KeyDescription<'_> {
    pub(crate) const fn validated(value: &str) -> KeyDescription<'_> {
        KeyDescription(value)
    }
}
impl AsRef<str> for KeyDescription<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}
impl fmt::Display for KeyDescription<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
