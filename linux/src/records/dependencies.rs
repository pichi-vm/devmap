// SPDX-License-Identifier: Apache-2.0

use std::io;

use super::Records;
use crate::{DevId, abi::Command};

/// Owned device dependencies, available through [`super::Records`].
pub(crate) struct Dependencies<const N: usize = 4096> {
    command: Command<N>,
    cursor: usize,
}

impl<const N: usize> Dependencies<N> {
    pub(crate) fn new(command: Command<N>) -> io::Result<Self> {
        let payload = command.payload()?;
        if payload.is_empty() {
            return Ok(Self { command, cursor: 0 });
        }
        if payload.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated dependency header",
            ));
        }
        let count = u32::from_ne_bytes(payload[..4].try_into().unwrap()) as usize;
        if count > (payload.len() - 8) / 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated dependency array",
            ));
        }
        Ok(Self { command, cursor: 0 })
    }
}

impl<const N: usize> Records for Dependencies<N> {
    type Item<'a> = DevId;

    fn next(&mut self) -> Option<io::Result<Self::Item<'_>>> {
        let payload = self.command.payload().expect("validated immutable reply");
        if payload.is_empty() {
            return None;
        }
        let count = u32::from_ne_bytes(payload[..4].try_into().unwrap()) as usize;
        if self.cursor >= count {
            return None;
        }
        let start = 8 + self.cursor * 8;
        self.cursor += 1;
        Some(Ok(DevId::from_kernel(u64::from_ne_bytes(
            payload[start..start + 8].try_into().unwrap(),
        ))))
    }
}

impl<const N: usize> std::fmt::Debug for Dependencies<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dependencies")
            .field("capacity", &N)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;
    use crate::abi::Header;

    #[test]
    fn header_only_reply_has_no_dependencies() {
        let mut header = Header::any();
        header.as_mut_bytes()[12..16].copy_from_slice(&305u32.to_ne_bytes());
        let mut reply = Dependencies::new(Command::<0>::new(header)).unwrap();
        assert!(reply.next().is_none());
        assert!(reply.next().is_none());
    }

    #[test]
    fn dependencies_validate_counts_before_borrowed_iteration() {
        fn collect(reply: &mut impl for<'a> Records<Item<'a> = DevId>) -> Vec<DevId> {
            let mut devices = Vec::new();
            while let Some(device) = reply.next() {
                devices.push(device.unwrap());
            }
            devices
        }
        let mut data = [0; 24];
        data[..4].copy_from_slice(&2u32.to_ne_bytes());
        data[8..16].copy_from_slice(&0xfc01u64.to_ne_bytes());
        data[16..24].copy_from_slice(&0xfc02u64.to_ne_bytes());
        let mut header = Header::any();
        header.as_mut_bytes()[12..16].copy_from_slice(
            &u32::try_from(Header::SIZE + data.len())
                .unwrap()
                .to_ne_bytes(),
        );
        let mut reply = Dependencies::new(Command::from_parts(header, data)).unwrap();
        assert_eq!(
            collect(&mut reply),
            [DevId::new(252, 1).unwrap(), DevId::new(252, 2).unwrap()]
        );
        data[..4].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(
            Dependencies::new(Command::from_parts(header, data))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
