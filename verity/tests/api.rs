// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Cursor, Read as _, Seek as _, SeekFrom};
use std::num::{NonZeroU32, NonZeroU64};

use devmap_verity::traits::std::{
    Format as _, Geometry as _, Open as _, OpenHashes as _, Scale as _, Slice as _,
};
use devmap_verity::{Algorithm, HashType, Hashes, Parameters, Verity};

fn bytes(blocks: usize, block_size: usize) -> Vec<u8> {
    (0..blocks * block_size)
        .map(|index| u8::try_from(index % 251).expect("modulo 251 fits in u8"))
        .collect()
}

fn format(data: &[u8], block_size: u32) -> (Vec<u8>, Box<[u8]>) {
    let block_size = NonZeroU32::new(block_size).unwrap();
    let count = data.len() as u64 / u64::from(block_size.get());
    let data = Cursor::new(data).scale(block_size).unwrap();
    let mut hashes = Cursor::new(Vec::new()).scale(block_size).unwrap();
    let (_, root) = Parameters::builder()
        .salt(&[7; 32])
        .data_block_size(block_size.get())
        .unwrap()
        .hash_block_size(block_size.get())
        .unwrap()
        .build(NonZeroU64::new(count).unwrap())
        .unwrap()
        .format(data, &mut hashes, [0x5a; 16])
        .unwrap();
    (hashes.into_inner().into_inner(), root)
}

#[test]
fn format_accepts_a_stream_and_returns_the_trusted_root() {
    let data = bytes(257, 512);
    let (hashes, root) = format(&data, 512);
    assert_eq!(root.len(), 32);
    assert_eq!(hashes.len() % 512, 0);
    assert!(hashes.len() > 512);
}

#[test]
fn format_uses_explicit_parameters_with_compatible_endpoints() {
    let data = bytes(3, 512);
    let data_block_size = NonZeroU32::new(512).unwrap();
    let hash_block_size = NonZeroU32::new(4096).unwrap();
    let input = Cursor::new(&data).scale(data_block_size).unwrap();
    let mut hashes = Cursor::new(Vec::new()).scale(hash_block_size).unwrap();

    let (_, root) = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(4096)
        .unwrap()
        .build(NonZeroU64::new(3).unwrap())
        .unwrap()
        .format(input, &mut hashes, [0; 16])
        .unwrap();
    let encoded = hashes.as_ref().get_ref();
    assert_eq!(u32::from_le_bytes(encoded[64..68].try_into().unwrap()), 512);
    assert_eq!(
        u32::from_le_bytes(encoded[68..72].try_into().unwrap()),
        4096
    );
    assert_eq!(u64::from_le_bytes(encoded[72..80].try_into().unwrap()), 3);

    hashes.rewind().unwrap();
    let input = Cursor::new(data.clone()).scale(data_block_size).unwrap();
    let mut device = Verity::open(input, Hashes::open(hashes).unwrap(), &root).unwrap();
    let mut actual = Vec::new();
    device.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, data);
}

#[test]
fn authenticated_reads_and_seeks_reproduce_the_data() {
    let data = bytes(257, 512);
    let (hashes, root) = format(&data, 512);
    let mut device = Verity::open(
        Cursor::new(data.clone()),
        Hashes::open(Cursor::new(hashes)).unwrap(),
        &root,
    )
    .unwrap();

    assert_eq!(device.count().unwrap(), data.len() as u64);
    assert_eq!(device.block_size().unwrap().get(), 1);
    device.seek(SeekFrom::Start(511)).unwrap();
    let mut crossing = [0; 1026];
    device.read_exact(&mut crossing).unwrap();
    assert_eq!(&crossing, &data[511..1537]);
    device.seek(SeekFrom::End(-16)).unwrap();
    let mut tail = Vec::new();
    device.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, data[data.len() - 16..]);
}

#[test]
fn endpoint_regions_define_independent_data_and_hash_devices() {
    let payload = bytes(3, 512);
    let block_size = NonZeroU32::new(512).unwrap();
    let data_view = Cursor::new(payload.clone()).scale(block_size).unwrap();
    let mut hash_view = Cursor::new(Vec::new()).scale(block_size).unwrap();
    let (_, root) = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(3).unwrap())
        .unwrap()
        .format(data_view, &mut hash_view, [0; 16])
        .unwrap();

    let hashes = hash_view.into_inner().into_inner();
    let data = Cursor::new([vec![0xaa; 512], payload.clone()].concat())
        .scale(block_size)
        .unwrap()
        .slice(1..4)
        .unwrap();
    let hash_blocks = u64::try_from(hashes.len() / 512).unwrap();
    let hashes = Cursor::new([vec![0xbb; 512], hashes].concat())
        .scale(block_size)
        .unwrap()
        .slice(1..1 + hash_blocks)
        .unwrap();
    let mut device = Verity::open(data, Hashes::open(hashes).unwrap(), &root).unwrap();
    let mut actual = Vec::new();
    device.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, payload);
}

#[test]
fn reading_rejects_an_untrusted_root() {
    let data = bytes(3, 512);
    let (hashes, mut root) = format(&data, 512);
    root[0] ^= 1;
    let mut device = Verity::open(
        Cursor::new(data),
        Hashes::open(Cursor::new(hashes)).unwrap(),
        &root,
    )
    .unwrap();
    let error = device.read(&mut [0; 1]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn reads_reject_corrupt_data_and_tree_blocks() {
    let data = bytes(257, 512);
    let (hashes, root) = format(&data, 512);

    let mut corrupt_data = data.clone();
    corrupt_data[200 * 512] ^= 1;
    let mut device = Verity::open(
        Cursor::new(corrupt_data),
        Hashes::open(Cursor::new(hashes.clone())).unwrap(),
        &root,
    )
    .unwrap();
    device.seek(SeekFrom::Start(200 * 512)).unwrap();
    assert_eq!(
        device.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    let mut corrupt_tree = hashes;
    *corrupt_tree.last_mut().unwrap() ^= 1;
    let mut device = Verity::open(
        Cursor::new(data),
        Hashes::open(Cursor::new(corrupt_tree)).unwrap(),
        &root,
    )
    .unwrap();
    device.seek(SeekFrom::Start(256 * 512)).unwrap();
    assert_eq!(
        device.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn open_rejects_each_malformed_superblock_field() {
    let data = bytes(3, 512);
    let (canonical, _) = format(&data, 512);
    let corruptions: &[(usize, &[u8])] = &[
        (0, b"x"),
        (8, &2u32.to_le_bytes()),
        (12, &2u32.to_le_bytes()),
        (32, b"x"),
        (64, &513u32.to_le_bytes()),
        (68, &513u32.to_le_bytes()),
        (72, &0u64.to_le_bytes()),
        (80, &257u16.to_le_bytes()),
        (82, &[1]),
        (120, &[1]),
        (344, &[1]),
    ];

    for &(offset, replacement) in corruptions {
        let mut hashes = canonical.clone();
        hashes[offset..offset + replacement.len()].copy_from_slice(replacement);
        let error = Hashes::open(Cursor::new(hashes)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "offset {offset}");
    }
}

#[test]
fn open_rejects_truncated_endpoints() {
    let data = bytes(3, 512);
    let (hashes, root) = format(&data, 512);
    for (data, hashes) in [
        (data[..data.len() - 1].to_vec(), hashes.clone()),
        (data.clone(), hashes[..hashes.len() - 1].to_vec()),
    ] {
        let error = Verity::open(
            Cursor::new(data),
            Hashes::open(Cursor::new(hashes)).unwrap(),
            &root,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn composition_checks_root_length_and_both_endpoint_block_sizes() {
    let data = bytes(4, 512);
    let (storage, root) = format(&data, 512);
    let hashes = Hashes::open(Cursor::new(storage.clone())).unwrap();
    let error = Verity::open(Cursor::new(&data), hashes, &root[..31])
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    let large_block = NonZeroU32::new(1024).unwrap();
    let hashes = Hashes::open(Cursor::new(storage.clone()).scale(large_block).unwrap()).unwrap();
    assert_eq!(hashes.parameters().hash_block_size().get(), 512);
    let error = Verity::open(Cursor::new(&data), hashes, &root)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let hashes = Hashes::open(Cursor::new(storage)).unwrap();
    let error = Verity::open(
        Cursor::new(&data).scale(large_block).unwrap(),
        hashes,
        &root,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn format_rejects_short_input_and_leaves_trailing_bytes_unread() {
    struct Short(Cursor<Vec<u8>>);

    impl io::Read for Short {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0.read(output)
        }
    }

    impl devmap_verity::traits::std::Geometry for Short {
        fn block_size(&self) -> io::Result<NonZeroU32> {
            Ok(NonZeroU32::new(512).unwrap())
        }

        fn count(&mut self) -> io::Result<u64> {
            Ok(1)
        }
    }

    let hashes = Cursor::new(Vec::new())
        .scale(NonZeroU32::new(512).unwrap())
        .unwrap();
    let error = Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(1).unwrap())
        .unwrap()
        .format(Short(Cursor::new(vec![0; 511])), hashes, [0; 16])
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

    let mut input = Cursor::new(vec![0; 513]);
    let data = (&mut input)
        .slice(0..512)
        .unwrap()
        .scale(NonZeroU32::new(512).unwrap())
        .unwrap();
    let hashes = Cursor::new(Vec::new())
        .scale(NonZeroU32::new(512).unwrap())
        .unwrap();
    Parameters::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build(NonZeroU64::new(1).unwrap())
        .unwrap()
        .format(data, hashes, [0; 16])
        .unwrap();
    assert_eq!(input.position(), 512);
}

#[test]
fn format_rejects_incompatible_geometry_and_empty_input() {
    struct InvalidGeometry(Cursor<Vec<u8>>);

    impl io::Read for InvalidGeometry {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.0.read(output)
        }
    }

    impl devmap_verity::traits::std::Geometry for InvalidGeometry {
        fn block_size(&self) -> io::Result<NonZeroU32> {
            Ok(NonZeroU32::new(513).unwrap())
        }

        fn count(&mut self) -> io::Result<u64> {
            Ok(1)
        }
    }

    let data = InvalidGeometry(Cursor::new(vec![0; 513]));
    let hashes = Cursor::new(Vec::new())
        .scale(NonZeroU32::new(512).unwrap())
        .unwrap();
    assert_eq!(
        Parameters::builder()
            .data_block_size(512)
            .unwrap()
            .hash_block_size(512)
            .unwrap()
            .build(NonZeroU64::new(1).unwrap())
            .unwrap()
            .format(data, hashes, [0; 16])
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let block_size = NonZeroU32::new(512).unwrap();
    let data = Cursor::new(Vec::new()).scale(block_size).unwrap();
    let hashes = Cursor::new(Vec::new()).scale(block_size).unwrap();
    assert_eq!(
        Parameters::builder()
            .data_block_size(512)
            .unwrap()
            .hash_block_size(512)
            .unwrap()
            .build(NonZeroU64::new(1).unwrap())
            .unwrap()
            .format(data, hashes, [0; 16])
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );

    let block_size = NonZeroU32::new(4096).unwrap();
    let data = Cursor::new(vec![0; 4096]).scale(block_size).unwrap();
    let hashes = Cursor::new(Vec::new()).scale(block_size).unwrap();
    let (_, root) = Parameters::builder()
        .algorithm(Algorithm::Sha256)
        .hash_type(HashType::Normal)
        .data_block_size(4096)
        .unwrap()
        .hash_block_size(4096)
        .unwrap()
        .build(NonZeroU64::new(1).unwrap())
        .unwrap()
        .format(data, hashes, [0; 16])
        .unwrap();
    assert_eq!(root.len(), 32);
}

#[test]
fn algorithm_names_are_stable_format_values() {
    for (name, algorithm) in [
        ("sha1", Algorithm::Sha1),
        ("sha256", Algorithm::Sha256),
        ("rmd160", Algorithm::Ripemd160),
        ("wp512", Algorithm::Whirlpool),
        ("sha3-512", Algorithm::Sha3_512),
        ("streebog256", Algorithm::Streebog256),
        ("sm3", Algorithm::Sm3),
        ("blake2s-256", Algorithm::Blake2s256),
    ] {
        assert_eq!(name.parse::<Algorithm>().unwrap(), algorithm);
        assert_eq!(algorithm.as_ref(), name);
        assert_eq!(algorithm.to_string(), name);
    }
}
