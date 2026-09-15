// SPDX-License-Identifier: Apache-2.0

use super::{Builder, CorruptionPolicy, Fec, IoErrorPolicy, VerityTarget};
use crate::HashType;
use devmap_core::{DevId, ParseError};
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

    fn unhex(value: &str) -> Result<Vec<u8>, ParseError> {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(ParseError),
        };
        let bytes = value.as_bytes();
        if bytes.len() % 2 != 0 {
            return Err(ParseError);
        }
        bytes
            .chunks_exact(2)
            .map(|pair| Ok(nibble(pair[0])? * 16 + nibble(pair[1])?))
            .collect()
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

    fn words(input: &str) -> Result<Vec<String>, ParseError> {
        if input.contains('\0') {
            return Err(ParseError);
        }
        let mut words = Vec::new();
        let mut word = String::new();
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\\' {
                word.push(chars.next().unwrap_or('\\'));
            } else if c.is_ascii_whitespace() {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            } else {
                word.push(c);
            }
        }
        if !word.is_empty() {
            words.push(word);
        }
        Ok(words)
    }

    fn device(value: &str) -> Result<DevId, ParseError> {
        if let Ok(id) = value.parse() {
            return Ok(id);
        }
        #[cfg(target_os = "linux")]
        {
            DevId::from_path(value).map_err(|_| ParseError)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ParseError)
        }
    }
}

impl fmt::Display for VerityTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} ",
            self.hash_type(),
            self.data_dev,
            self.hash_dev,
            self.data_block_size(),
            self.hash_block_size(),
            self.data_blocks,
            self.hash_start_block(),
            self.algorithm()
        )?;
        Self::hex(f, &self.root)?;
        f.write_char(' ')?;
        if self.salt().is_empty() {
            f.write_str("-")?;
        } else {
            Self::hex(f, self.salt())?;
        }
        let s = &self.settings;
        let count = usize::from(s.corruption != CorruptionPolicy::Error)
            + usize::from(s.io_error != IoErrorPolicy::Error)
            + usize::from(s.ignore_zero)
            + usize::from(s.at_most_once)
            + usize::from(s.tasklet)
            + usize::from(s.fec.is_some()) * 8
            + usize::from(s.signature.is_some()) * 2;
        if count == 0 {
            return Ok(());
        }
        write!(f, " {count}")?;
        match s.corruption {
            CorruptionPolicy::Error => {}
            CorruptionPolicy::Ignore => f.write_str(" ignore_corruption")?,
            CorruptionPolicy::Restart => f.write_str(" restart_on_corruption")?,
            CorruptionPolicy::Panic => f.write_str(" panic_on_corruption")?,
        }
        match s.io_error {
            IoErrorPolicy::Error => {}
            IoErrorPolicy::Restart => f.write_str(" restart_on_error")?,
            IoErrorPolicy::Panic => f.write_str(" panic_on_error")?,
        }
        if s.ignore_zero {
            f.write_str(" ignore_zero_blocks")?;
        }
        if s.at_most_once {
            f.write_str(" check_at_most_once")?;
        }
        if s.tasklet {
            f.write_str(" try_verify_in_tasklet")?;
        }
        if let Some(fec) = &s.fec {
            write!(
                f,
                " use_fec_from_device {} fec_roots {} fec_blocks {} fec_start {}",
                fec.device, fec.roots, fec.blocks, fec.start
            )?;
        }
        if let Some(key) = &s.signature {
            f.write_str(" root_hash_sig_key_desc ")?;
            Self::token(f, key)?;
        }
        Ok(())
    }
}

impl FromStr for VerityTarget {
    type Err = ParseError;
    // Keep option counts, ordering, and conflict checks in one parser.
    #[allow(clippy::too_many_lines)]
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let words = Self::words(input)?;
        if words.len() < 10 {
            return Err(ParseError);
        }
        let hash_type = match words[0].as_str() {
            "0" => HashType::ChromeOs,
            "1" => HashType::Normal,
            _ => return Err(ParseError),
        };
        let data = Self::device(&words[1])?;
        let hashes = Self::device(&words[2])?;
        let count = words[5]
            .parse::<u64>()
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(ParseError)?;
        let mut builder = Builder::new(count)
            .hash_type(hash_type)
            .data_block_size(words[3].parse().map_err(|_| ParseError)?)
            .map_err(|_| ParseError)?
            .hash_block_size(words[4].parse().map_err(|_| ParseError)?)
            .map_err(|_| ParseError)?
            .hash_start_block(words[6].parse().map_err(|_| ParseError)?)
            .algorithm(&words[7])
            .map_err(|_| ParseError)?;
        let root = Self::unhex(&words[8])?;
        if words[9] != "-" {
            builder = builder.salt(&Self::unhex(&words[9])?);
        }
        if words.len() > 10 {
            let extra: usize = words[10].parse().map_err(|_| ParseError)?;
            if extra != words.len() - 11 {
                return Err(ParseError);
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
            let mut value = || -> Result<&str, ParseError> {
                let value = words.get(index).ok_or(ParseError)?;
                index += 1;
                Ok(value)
            };
            match option.as_str() {
                "ignore_corruption" | "restart_on_corruption" | "panic_on_corruption" => {
                    if corruption {
                        return Err(ParseError);
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
                        return Err(ParseError);
                    }
                    io_error = true;
                    builder = builder.io_error_policy(if option == "restart_on_error" {
                        IoErrorPolicy::Restart
                    } else {
                        IoErrorPolicy::Panic
                    });
                }
                "ignore_zero_blocks" => builder = builder.ignore_zero_blocks(true),
                "check_at_most_once" => builder = builder.check_at_most_once(true),
                "try_verify_in_tasklet" => builder = builder.try_verify_in_tasklet(true),
                "root_hash_sig_key_desc" => {
                    if signature {
                        return Err(ParseError);
                    }
                    signature = true;
                    builder = builder
                        .root_hash_sig_key_desc(value()?)
                        .map_err(|_| ParseError)?;
                }
                "use_fec_from_device" => {
                    if fec_device.is_some() {
                        return Err(ParseError);
                    }
                    fec_device = Some(Self::device(value()?)?);
                }
                "fec_roots" => fec_roots = Some(value()?.parse().map_err(|_| ParseError)?),
                "fec_blocks" => {
                    fec_blocks = Some(
                        value()?
                            .parse::<u64>()
                            .ok()
                            .and_then(NonZeroU64::new)
                            .ok_or(ParseError)?,
                    );
                }
                "fec_start" => fec_start = value()?.parse().map_err(|_| ParseError)?,
                _ => return Err(ParseError),
            }
        }
        if fec_device.is_some() || fec_roots.is_some() || fec_blocks.is_some() || fec_start != 0 {
            builder = builder.fec(
                Fec::new(
                    fec_device.ok_or(ParseError)?,
                    fec_blocks.ok_or(ParseError)?,
                    fec_roots.ok_or(ParseError)?,
                )
                .map_err(|_| ParseError)?
                .start(fec_start),
            );
        }
        builder.build(data, hashes, &root).map_err(|_| ParseError)
    }
}
