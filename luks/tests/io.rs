// SPDX-License-Identifier: Apache-2.0

use devmap_luks::{Hash, Header};
use std::io::Cursor;

fn luks1() -> Vec<u8> {
    let mut bytes = vec![0; 592];
    bytes[..6].copy_from_slice(&devmap_luks::LUKS_MAGIC);
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes[8..11].copy_from_slice(b"aes");
    bytes[40..51].copy_from_slice(b"xts-plain64");
    bytes[72..78].copy_from_slice(b"sha256");
    bytes[104..108].copy_from_slice(&4096u32.to_be_bytes());
    bytes[108..112].copy_from_slice(&64u32.to_be_bytes());
    for slot in 0..8 {
        bytes[208 + slot * 48..212 + slot * 48].copy_from_slice(&0xdeadu32.to_be_bytes());
    }
    bytes
}

#[test]
fn reader_accepts_exact_luks1_records_and_calculates_payload() {
    let mut bytes = Cursor::new(luks1());
    let header = Header::open(&mut bytes).unwrap();
    assert_eq!(bytes.position(), 592);
    let offset = header.payload_offset_bytes().unwrap();
    assert!(header.payload_sectors(offset).is_err());
    assert!(header.payload_sectors(offset - 1).is_err());
    assert!(header.payload_sectors(offset + 511).is_err());
    assert_eq!(header.payload_sectors(offset + 1024).unwrap(), 2);
}

#[test]
fn reader_covers_large_luks2_copies_and_recovers_from_a_bad_primary_checksum() {
    let size = 512 * 1024;
    let mut bytes = vec![0; size * 2];
    let json = br#"{"keyslots":{},"digests":{},"segments":{}}"#;
    for copy in 0..2 {
        let base = copy * size;
        let magic = if copy == 0 {
            devmap_luks::LUKS_MAGIC
        } else {
            devmap_luks::LUKS2_SECONDARY_MAGIC
        };
        bytes[base..base + 6].copy_from_slice(&magic);
        bytes[base + 6..base + 8].copy_from_slice(&2u16.to_be_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&(size as u64).to_be_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&(copy as u64 + 1).to_be_bytes());
        bytes[base + 72..base + 78].copy_from_slice(b"sha256");
        bytes[base + 4096..base + 4096 + json.len()].copy_from_slice(json);
        let digest = Hash::Sha256.digest(&bytes[base..base + size]);
        bytes[base + 448..base + 480].copy_from_slice(&digest);
    }
    bytes[448] ^= 1;
    let mut storage = Cursor::new(bytes);
    let header = Header::open(&mut storage).unwrap();
    assert_eq!(storage.position(), (size * 2) as u64);
    let Header::V2(header) = header else {
        panic!("expected LUKS2");
    };
    assert_eq!(header.seqid, 2);
}

#[test]
fn reader_rejects_unbounded_header_allocations() {
    let mut bytes = vec![0; 16];
    bytes[..6].copy_from_slice(&devmap_luks::LUKS_MAGIC);
    bytes[6..8].copy_from_slice(&2u16.to_be_bytes());
    bytes[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(Header::open(Cursor::new(bytes)).is_err());
}

#[cfg(feature = "devmap-crypt")]
#[test]
fn crypt_parameters_come_from_the_header() {
    let header = Header::open(Cursor::new(luks1())).unwrap();
    let id = devmap_core::parse::DevId::new(7, 1).unwrap();
    let key = devmap_crypt::dm::Key::Keyring {
        size: 64,
        kind: devmap_crypt::dm::KeyType::Logon,
        description: "test:volume".into(),
    };
    let target = header.crypt_target(id, key).unwrap();
    assert_eq!(target.offset, 4096);
    assert_eq!(target.iv_offset, 0);
    assert_eq!(target.sector_size, None);
    assert!(target.to_string().contains("aes-xts-plain64"));
}
