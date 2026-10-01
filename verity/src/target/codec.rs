// SPDX-License-Identifier: Apache-2.0

use super::VerityTarget;
use super::{CorruptionPolicy, IoErrorPolicy};
use crate::header::{Constraint, HashType, Header, Salt};
use devmap_core::BlockSize;
use devmap_linux::{DevId, ParseError as Error};
use std::borrow::Cow;
use std::{
    fmt::{self, Write as _},
    num::NonZero,
    str::FromStr,
};

impl VerityTarget {
    fn hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
        for byte in bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }

    fn chars(value: &str) -> impl Iterator<Item = char> + '_ {
        let mut chars = value.chars();
        std::iter::from_fn(move || {
            chars.next().map(|c| {
                if c == '\\' {
                    chars.next().unwrap_or(c)
                } else {
                    c
                }
            })
        })
    }

    fn unhex(value: &str) -> impl Iterator<Item = Result<u8, Error>> + '_ {
        let mut chars = Self::chars(value);
        std::iter::from_fn(move || {
            let first = chars.next()?;
            Some((|| {
                let high = first
                    .to_digit(16)
                    .filter(|_| first.is_ascii())
                    .ok_or(Error)?;
                let last = chars.next().ok_or(Error)?;
                let low = last.to_digit(16).filter(|_| last.is_ascii()).ok_or(Error)?;
                Ok((high * 16 + low) as u8)
            })())
        })
    }

    fn word(value: &str) -> Cow<'_, str> {
        if value.contains('\\') {
            Cow::Owned(Self::chars(value).collect())
        } else {
            Cow::Borrowed(value)
        }
    }

    fn token(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
        for c in value.chars() {
            if c == '\\' || c.is_ascii_whitespace() {
                f.write_char('\\')?;
            }
            f.write_char(c)?;
        }
        Ok(())
    }

    fn words(input: &str) -> Result<Vec<&str>, Error> {
        if input.contains('\0') {
            return Err(Error);
        }
        let mut words = Vec::new();
        let mut start = None;
        let mut escaped = false;
        for (index, c) in input.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c.is_ascii_whitespace() {
                if let Some(start) = start.take() {
                    words.push(&input[start..index]);
                }
            } else {
                start.get_or_insert(index);
                escaped = c == '\\';
            }
        }
        if let Some(start) = start {
            words.push(&input[start..]);
        }
        Ok(words)
    }

    fn device(value: &str) -> Result<DevId, Error> {
        if let Ok(id) = value.parse() {
            return Ok(id);
        }
        #[cfg(target_os = "linux")]
        {
            std::fs::metadata(value)
                .and_then(DevId::try_from)
                .map_err(|_| Error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error)
        }
    }
}

impl fmt::Display for VerityTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} ",
            self.hash_type,
            self.data,
            self.hash,
            self.geometry.size.bytes(),
            self.block.bytes(),
            self.geometry.count,
            self.hash_start,
            self.algorithm
        )?;
        Self::hex(f, &self.root)?;
        f.write_char(' ')?;
        if self.salt.is_empty() {
            f.write_str("-")?;
        } else {
            Self::hex(f, self.salt.as_ref())?;
        }
        let count = usize::from(self.corruption_policy != CorruptionPolicy::Error)
            + usize::from(self.io_error_policy != IoErrorPolicy::Error)
            + usize::from(self.ignore_zero_blocks)
            + usize::from(self.check_at_most_once)
            + usize::from(self.try_verify_in_tasklet)
            + usize::from(self.signature.is_some()) * 2;
        if count == 0 {
            return Ok(());
        }
        write!(f, " {count}")?;
        match self.corruption_policy {
            CorruptionPolicy::Error => {}
            CorruptionPolicy::Ignore => f.write_str(" ignore_corruption")?,
            CorruptionPolicy::Restart => f.write_str(" restart_on_corruption")?,
            CorruptionPolicy::Panic => f.write_str(" panic_on_corruption")?,
        }
        match self.io_error_policy {
            IoErrorPolicy::Error => {}
            IoErrorPolicy::Restart => f.write_str(" restart_on_error")?,
            IoErrorPolicy::Panic => f.write_str(" panic_on_error")?,
        }
        if self.ignore_zero_blocks {
            f.write_str(" ignore_zero_blocks")?;
        }
        if self.check_at_most_once {
            f.write_str(" check_at_most_once")?;
        }
        if self.try_verify_in_tasklet {
            f.write_str(" try_verify_in_tasklet")?;
        }
        if let Some(key) = &self.signature {
            f.write_str(" root_hash_sig_key_desc ")?;
            Self::token(f, key)?;
        }
        Ok(())
    }
}

impl FromStr for VerityTarget {
    type Err = Error;
    // Keep option counts, ordering, and conflict checks in one parser.
    #[allow(clippy::too_many_lines)]
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw = Self::words(input)?;
        // Keep the salt token borrowed even when escaped; decode it directly below.
        let words: Vec<_> = raw
            .iter()
            .enumerate()
            .map(|(i, word)| {
                if i == 9 {
                    Cow::Borrowed(*word)
                } else {
                    Self::word(word)
                }
            })
            .collect();
        if words.len() < 10 {
            return Err(Error);
        }
        let hash_type = match words[0].as_ref() {
            "0" => HashType::ChromeOs,
            "1" => HashType::Normal,
            _ => return Err(Error),
        };
        let data = Self::device(&words[1])?;
        let hash = Self::device(&words[2])?;
        let count = words[5]
            .parse::<u64>()
            .ok()
            .and_then(NonZero::<u64>::new)
            .ok_or(Error)?;
        let mut header = Header {
            uuid: [0; 16],
            hash_type,
            algorithm: words[7].parse().map_err(|_| Error)?,
            salt: Salt::default(),
            data: devmap_core::Geometry {
                size: BlockSize::default(),
                count,
            },
            hash: BlockSize::default(),
        };
        let data_block_size = words[3]
            .parse::<u32>()
            .ok()
            .and_then(NonZero::new)
            .and_then(BlockSize::<Constraint>::from_bytes)
            .ok_or(Error)?;
        let hash_block_size = words[4]
            .parse::<u32>()
            .ok()
            .and_then(NonZero::new)
            .and_then(BlockSize::<Constraint>::from_bytes)
            .ok_or(Error)?;
        header.data.size = data_block_size;
        header.hash = hash_block_size;
        let root = Self::unhex(&words[8]).collect::<Result<Vec<_>, _>>()?;
        if !Self::chars(&words[9]).eq("-".chars()) {
            let salt = Self::unhex(&words[9]).collect::<Result<Vec<_>, _>>()?;
            header.salt = Salt::new(&salt).ok_or(Error)?;
        }
        let mut builder = header
            .builder(data, hash, root)
            .map_err(|_| Error)?
            .hash_start(words[6].parse()?)
            .map_err(|_| Error)?;
        if words.len() > 10 {
            let extra: usize = words[10].parse().map_err(|_| Error)?;
            if extra != words.len() - 11 {
                return Err(Error);
            }
        }
        let mut index = 11;
        let mut corruption = false;
        let mut io_error = false;
        let mut signature = false;
        while index < words.len() {
            let option = words[index].to_ascii_lowercase();
            index += 1;
            let mut value = || -> Result<&str, Error> {
                let value = words.get(index).ok_or(Error)?;
                index += 1;
                Ok(value.as_ref())
            };
            match option.as_str() {
                "ignore_corruption" | "restart_on_corruption" | "panic_on_corruption" => {
                    if corruption {
                        return Err(Error);
                    }
                    corruption = true;
                    builder = builder.corruption_policy(match option.as_str() {
                        "ignore_corruption" => CorruptionPolicy::Ignore,
                        "restart_on_corruption" => CorruptionPolicy::Restart,
                        _ => CorruptionPolicy::Panic,
                    });
                }
                "restart_on_error" | "panic_on_error" => {
                    if io_error {
                        return Err(Error);
                    }
                    io_error = true;
                    builder = builder.io_error_policy(if option == "restart_on_error" {
                        IoErrorPolicy::Restart
                    } else {
                        IoErrorPolicy::Panic
                    });
                }
                "ignore_zero_blocks" => builder = builder.ignore_zero_blocks(true),
                "check_at_most_once" => {
                    builder = builder.check_at_most_once(true).map_err(|_| Error)?;
                }
                "try_verify_in_tasklet" => builder = builder.try_verify_in_tasklet(true),
                "root_hash_sig_key_desc" => {
                    if signature {
                        return Err(Error);
                    }
                    signature = true;
                    builder = builder
                        .root_hash_sig_key_desc(value()?)
                        .map_err(|_| Error)?;
                }
                _ => return Err(Error),
            }
        }
        Ok(builder.build())
    }
}
