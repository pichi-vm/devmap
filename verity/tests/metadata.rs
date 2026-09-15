// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use devmap_verity::{HashType, Hashes, traits::std::OpenHashes as _};

mod common;

#[test]
fn every_algorithm_header_is_available_independently_of_hash_features() {
    for &(name, algorithm, _) in common::ALGORITHMS {
        assert_eq!(name.parse::<devmap_verity::Algorithm>().unwrap(), algorithm);
        assert_eq!(algorithm.as_ref(), name);
        let hashes = Hashes::open(Cursor::new(common::header(name))).unwrap();
        let header = hashes.parameters();
        assert_eq!(header.algorithm(), algorithm);
        assert_eq!(header.hash_type(), HashType::Normal);
        assert_eq!(hashes.uuid(), [0x5a; 16]);
        assert_eq!(header.data_block_size().get(), 512);
        assert_eq!(header.hash_block_size().get(), 4096);
        assert_eq!(header.data_blocks().get(), 3);
        assert_eq!(header.salt(), [1, 2, 3]);
    }
}

// Deliberately has no Geometry implementation, and refuses reads outside the
// record. Short transfers exercise read_exact rather than an assumed full read.
struct HeaderOnly(Cursor<Vec<u8>>);

impl Read for HeaderOnly {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(
            self.0.position() < 512,
            "header inspection read beyond the record"
        );
        let limit = bytes.len().min(7);
        self.0.read(&mut bytes[..limit])
    }
}

impl Seek for HeaderOnly {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        assert!(
            matches!(position, SeekFrom::Start(0)),
            "inspection queried the extent"
        );
        self.0.seek(position)
    }
}

#[test]
fn inspection_requires_only_one_readable_seekable_endpoint() {
    let mut storage = HeaderOnly(Cursor::new(
        [common::header("sha256").to_vec(), vec![99; 4096]].concat(),
    ));
    storage.0.set_position(123);
    let hashes = Hashes::open(&mut storage).unwrap();
    assert_eq!(hashes.parameters().salt(), [1, 2, 3]);
    let storage = hashes.into_inner();
    assert_eq!(storage.0.position(), 512);
}

#[test]
fn all_block_sizes_and_hash_types_decode_without_implementations() {
    for &(name, _, _) in common::ALGORITHMS {
        for data_order in 9..=19 {
            for hash_order in 9..=19 {
                for hash_type in [0u32, 1] {
                    let mut bytes = common::header(name);
                    bytes[12..16].copy_from_slice(&hash_type.to_le_bytes());
                    bytes[64..68].copy_from_slice(&(1u32 << data_order).to_le_bytes());
                    bytes[68..72].copy_from_slice(&(1u32 << hash_order).to_le_bytes());
                    let hashes = Hashes::open(Cursor::new(bytes)).unwrap();
                    assert_eq!(hashes.parameters().data_block_size().get(), 1 << data_order);
                    assert_eq!(hashes.parameters().hash_block_size().get(), 1 << hash_order);
                    assert_eq!(
                        hashes.parameters().hash_type().to_string(),
                        hash_type.to_string()
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_fields_padding_and_overflow_are_rejected() {
    let corruptions: &[(usize, &[u8])] = &[
        (0, b"x"),
        (8, &2u32.to_le_bytes()),
        (12, &2u32.to_le_bytes()),
        (32, b"x"),
        (39, b"x"),
        (64, &0u32.to_le_bytes()),
        (64, &256u32.to_le_bytes()),
        (64, &513u32.to_le_bytes()),
        (64, &(1u32 << 20).to_le_bytes()),
        (68, &0u32.to_le_bytes()),
        (68, &256u32.to_le_bytes()),
        (68, &513u32.to_le_bytes()),
        (68, &(1u32 << 20).to_le_bytes()),
        (72, &0u64.to_le_bytes()),
        (72, &u64::MAX.to_le_bytes()),
        (80, &257u16.to_le_bytes()),
        (82, &[1]),
        (91, &[1]),
        (344, &[1]),
    ];
    for &(offset, replacement) in corruptions {
        let mut bytes = common::header("sha256");
        bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
        let error = Hashes::open(Cursor::new(bytes)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "offset {offset}");
    }
}

#[test]
fn salt_boundaries_and_largest_addressable_data_extent_are_valid() {
    for size in [0u16, 256] {
        let mut bytes = common::header("sha256");
        bytes[80..82].copy_from_slice(&size.to_le_bytes());
        bytes[88..344].fill(0);
        bytes[88..88 + usize::from(size)].fill(0xff);
        bytes[72..80].copy_from_slice(&(u64::MAX / 512).to_le_bytes());
        let hashes = Hashes::open(Cursor::new(bytes)).unwrap();
        assert_eq!(hashes.parameters().salt(), vec![0xff; usize::from(size)]);
    }
}

#[test]
fn truncated_headers_report_unexpected_eof() {
    for length in [0, 8, 88, 511] {
        let bytes = common::header("sha256");
        assert_eq!(
            Hashes::open(Cursor::new(&bytes[..length]))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[test]
fn transport_errors_are_preserved() {
    struct Failing;
    impl Seek for Failing {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "seek denied",
            ))
        }
    }
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }
    }
    assert_eq!(
        Hashes::open(Failing).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
}
