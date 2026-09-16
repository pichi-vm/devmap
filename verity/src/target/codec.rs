// SPDX-License-Identifier: Apache-2.0

use super::VerityTarget;
use crate::{
    CorruptionPolicy, Fec, HashType, IoErrorPolicy, KeyDescription, Options, Scheme, Shape,
};
use devmap_core::parse::{DevId, Error};
use std::borrow::Cow;
use std::{
    fmt::{self, Write as _},
    num::NonZeroU64,
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
            DevId::from_path(value).map_err(|_| Error)
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
            self.scheme.hash_type,
            self.data_dev,
            self.hash_dev,
            self.shape.data_block_size,
            self.shape.hash_block_size,
            self.shape.data_blocks,
            self.options.hash_start_block,
            self.scheme.algorithm
        )?;
        Self::hex(f, &self.root)?;
        f.write_char(' ')?;
        if self.scheme.salt.as_slice().is_empty() {
            f.write_str("-")?;
        } else {
            Self::hex(f, self.scheme.salt.as_slice())?;
        }
        let count = usize::from(self.options.corruption_policy != CorruptionPolicy::Error)
            + usize::from(self.options.io_error_policy != IoErrorPolicy::Error)
            + usize::from(self.options.ignore_zero_blocks)
            + usize::from(self.options.check_at_most_once)
            + usize::from(self.options.try_verify_in_tasklet)
            + usize::from(self.options.fec.is_some()) * 8
            + usize::from(self.signature.is_some()) * 2;
        if count == 0 {
            return Ok(());
        }
        write!(f, " {count}")?;
        match self.options.corruption_policy {
            CorruptionPolicy::Error => {}
            CorruptionPolicy::Ignore => f.write_str(" ignore_corruption")?,
            CorruptionPolicy::Restart => f.write_str(" restart_on_corruption")?,
            CorruptionPolicy::Panic => f.write_str(" panic_on_corruption")?,
        }
        match self.options.io_error_policy {
            IoErrorPolicy::Error => {}
            IoErrorPolicy::Restart => f.write_str(" restart_on_error")?,
            IoErrorPolicy::Panic => f.write_str(" panic_on_error")?,
        }
        if self.options.ignore_zero_blocks {
            f.write_str(" ignore_zero_blocks")?;
        }
        if self.options.check_at_most_once {
            f.write_str(" check_at_most_once")?;
        }
        if self.options.try_verify_in_tasklet {
            f.write_str(" try_verify_in_tasklet")?;
        }
        if let Some(fec) = &self.options.fec {
            write!(
                f,
                " use_fec_from_device {} fec_roots {} fec_blocks {} fec_start {}",
                fec.device(),
                fec.roots(),
                fec.blocks(),
                fec.start_block()
            )?;
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
        let hashes = Self::device(&words[2])?;
        let count = words[5]
            .parse::<u64>()
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(Error)?;
        let mut scheme = Scheme {
            hash_type,
            algorithm: words[7].parse().map_err(|_| Error)?,
            ..Scheme::default()
        };
        let shape = Shape {
            data_blocks: count,
            data_block_size: words[3].parse().map_err(|_| Error)?,
            hash_block_size: words[4].parse().map_err(|_| Error)?,
        };
        let root = Self::unhex(&words[8]).collect::<Result<Vec<_>, _>>()?;
        if !Self::chars(&words[9]).eq("-".chars()) {
            for byte in Self::unhex(&words[9]) {
                if scheme.salt.len() == 256 {
                    return Err(Error);
                }
                scheme.salt.push(byte?);
            }
        }
        let mut options = Options::default().with_hash_start_block(words[6].parse()?);
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
        let (mut fec_device, mut fec_roots, mut fec_blocks, mut fec_start) = (None, None, None, 0);
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
                    options = options.with_corruption_policy(match option.as_str() {
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
                    options = options.with_io_error_policy(if option == "restart_on_error" {
                        IoErrorPolicy::Restart
                    } else {
                        IoErrorPolicy::Panic
                    });
                }
                "ignore_zero_blocks" => options = options.with_ignore_zero_blocks(true),
                "check_at_most_once" => {
                    options = options.with_check_at_most_once(true);
                }
                "try_verify_in_tasklet" => options = options.with_try_verify_in_tasklet(true),
                "root_hash_sig_key_desc" => {
                    if signature {
                        return Err(Error);
                    }
                    signature = true;
                    options = options.with_root_hash_sig_key_desc(
                        KeyDescription::try_from(value()?).map_err(|_| Error)?,
                    );
                }
                "use_fec_from_device" => {
                    if fec_device.is_some() {
                        return Err(Error);
                    }
                    fec_device = Some(Self::device(value()?)?);
                }
                "fec_roots" => fec_roots = Some(value()?.parse().map_err(|_| Error)?),
                "fec_blocks" => {
                    fec_blocks = Some(
                        value()?
                            .parse::<u64>()
                            .ok()
                            .and_then(NonZeroU64::new)
                            .ok_or(Error)?,
                    );
                }
                "fec_start" => fec_start = value()?.parse().map_err(|_| Error)?,
                _ => return Err(Error),
            }
        }
        if fec_device.is_some() || fec_roots.is_some() || fec_blocks.is_some() || fec_start != 0 {
            options = options.with_fec(
                Fec::new(
                    fec_device.ok_or(Error)?,
                    fec_blocks.ok_or(Error)?,
                    fec_roots.ok_or(Error)?,
                )
                .map_err(|_| Error)?
                .start(fec_start),
            );
        }
        options
            .target(scheme, shape, data, hashes, &root)
            .map_err(|_| Error)
    }
}
