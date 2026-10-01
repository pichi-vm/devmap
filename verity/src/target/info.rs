// SPDX-License-Identifier: Apache-2.0

use devmap_linux::ParseError as Error;
use devmap_linux::{
    table::InfoMode,
    target::{Parse, Version},
};
use std::{fmt, str::FromStr};

/// Runtime corruption status and number of FEC-corrected blocks.
///
/// Target versions before 1.13 report only the corruption flag; later
/// versions also report the FEC correction count or `-` when FEC is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Whether any hash mismatch has occurred.
    pub corrupted: bool,
    /// Corrected blocks, or `None` if FEC is disabled.
    pub fec_corrected: Option<u64>,
}
impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", if self.corrupted { 'C' } else { 'V' })?;
        match self.fec_corrected {
            Some(count) => count.fmt(f),
            None => f.write_str("-"),
        }
    }
}
impl FromStr for Info {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fields = s.split_whitespace();
        let corrupted = match fields.next().ok_or(Error)? {
            "C" => true,
            "V" => false,
            _ => return Err(Error),
        };
        let fec_corrected = match fields.next().ok_or(Error)? {
            "-" => None,
            count => Some(count.parse()?),
        };
        if fields.next().is_some() {
            return Err(Error);
        }
        Ok(Self {
            corrupted,
            fec_corrected,
        })
    }
}

impl Parse<InfoMode> for Info {
    type Error = Error;

    fn parse(text: &str, version: Version) -> Result<Self, Self::Error> {
        if version.major != 1 {
            return Err(Error);
        }

        let status: Self = if version < Version::from([1, 13, 0]) {
            let corrupted = match text.trim() {
                "C" => true,
                "V" => false,
                _ => return Err(Error),
            };
            Self {
                corrupted,
                fec_corrected: None,
            }
        } else {
            text.parse()?
        };

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_info_parser_matches_the_kernel_status_grammar() {
        for status in ["V", "C"] {
            assert_eq!(
                <Info as Parse<InfoMode>>::parse(status, Version::from([1, 12, 0])),
                Ok(Info {
                    corrupted: status == "C",
                    fec_corrected: None,
                })
            );
            assert_eq!(
                <Info as Parse<InfoMode>>::parse(status, Version::from([1, 13, 0])),
                Err(Error)
            );
        }

        assert_eq!(
            <Info as Parse<InfoMode>>::parse("C 3", Version::from([1, 13, 0])),
            Ok(Info {
                corrupted: true,
                fec_corrected: Some(3)
            })
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("V -", Version::from([1, 13, 0])),
            Ok(Info::default())
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("C 3", Version::from([1, 12, 0])),
            Err(Error)
        );
        assert_eq!(
            <Info as Parse<InfoMode>>::parse("V -", Version::from([2, 0, 0])),
            Err(Error)
        );
    }
}
