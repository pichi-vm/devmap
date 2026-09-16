// SPDX-License-Identifier: Apache-2.0

use super::Unverified;
use crate::{HashType, Scheme, Shape, layout::Layout};
use std::{io, num::NonZeroU64};

impl Unverified {
    pub(crate) fn decode(&self) -> io::Result<([u8; 16], Layout)> {
        let bytes = self.as_ref();
        let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
        if bytes[..Unverified::VERSION] != Unverified::SIGNATURE {
            return Err(invalid("invalid verity signature"));
        }
        if u32::from_le_bytes(self.field(Unverified::VERSION)) != 1 {
            return Err(invalid("unsupported verity version"));
        }
        let hash_type = match u32::from_le_bytes(self.field(Unverified::HASH_TYPE)) {
            0 => HashType::ChromeOs,
            1 => HashType::Normal,
            _ => return Err(invalid("unsupported verity hash type")),
        };
        let name = &bytes[Unverified::ALGORITHM..Unverified::DATA_BLOCK_SIZE];
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        if name[end..].iter().any(|byte| *byte != 0) {
            return Err(invalid("invalid hash algorithm encoding"));
        }
        let algorithm = std::str::from_utf8(&name[..end])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .parse()?;
        let data_blocks = NonZeroU64::new(u64::from_le_bytes(self.field(Unverified::DATA_BLOCKS)))
            .ok_or_else(|| invalid("verity data block count must be nonzero"))?;
        let data_block_size = u32::from_le_bytes(self.field(Unverified::DATA_BLOCK_SIZE));
        let hash_block_size = u32::from_le_bytes(self.field(Unverified::HASH_BLOCK_SIZE));
        let salt_size = u16::from_le_bytes(self.field(Unverified::SALT_SIZE));
        if salt_size > 256 {
            return Err(invalid("salt exceeds 256 bytes"));
        }
        if bytes[Unverified::SALT_PADDING..Unverified::SALT]
            .iter()
            .chain(&bytes[Unverified::SALT + usize::from(salt_size)..Unverified::PADDING])
            .any(|byte| *byte != 0)
        {
            return Err(invalid("nonzero salt padding"));
        }
        if bytes[Unverified::PADDING..].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero verity superblock padding"));
        }
        let layout = (|| {
            let scheme = Scheme::default()
                .with_hash_type(hash_type)
                .with_algorithm(algorithm)
                .with_salt(&bytes[Unverified::SALT..Unverified::SALT + usize::from(salt_size)])?;
            let shape = Shape::new(data_blocks)
                .with_data_block_size(data_block_size.try_into()?)
                .with_hash_block_size(hash_block_size.try_into()?);
            let layout = Layout::new(&scheme, shape)?;
            layout.validate_header()?;
            Ok::<_, io::Error>(layout)
        })()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok((self.field(Unverified::UUID), layout))
    }
}
