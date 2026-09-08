// SPDX-License-Identifier: Apache-2.0

// These fixtures use bounded integer casts when checking the on-disk format.
#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::similar_names
)]

use devmap_verity::*;
use sha2::{Digest as _, Sha224, Sha256};
use std::io::{self, Cursor, Read, Seek, Write};
use std::num::NonZeroU64;

#[derive(Clone)]
struct Format {
    hash_type: HashType,
    algorithm: Algorithm,
    uuid: [u8; 16],
    data_block_size: u32,
    hash_block_size: u32,
    salt: Vec<u8>,
}

impl Default for Format {
    fn default() -> Self {
        Self {
            hash_type: HashType::Normal,
            algorithm: Algorithm::Sha256,
            uuid: [0; 16],
            data_block_size: 4096,
            hash_block_size: 4096,
            salt: Vec::new(),
        }
    }
}

impl Format {
    fn hash_type(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;
        self
    }

    fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    fn hash_block_size(mut self, hash_block_size: u32) -> Self {
        self.hash_block_size = hash_block_size;
        self
    }

    fn salt(mut self, salt: impl AsRef<[u8]>) -> Self {
        self.salt = salt.as_ref().to_vec();
        self
    }

    fn uuid(mut self, uuid: [u8; 16]) -> Self {
        self.uuid = uuid;
        self
    }

    fn build(&self, data_blocks: u64) -> Verified {
        Verified::builder()
            .algorithm(self.algorithm)
            .hash_type(self.hash_type)
            .data_block_size(self.data_block_size)
            .unwrap()
            .hash_block_size(self.hash_block_size)
            .unwrap()
            .salt(&self.salt)
            .unwrap()
            .build(self.uuid, NonZeroU64::new(data_blocks).unwrap())
            .unwrap()
    }
}

struct Output {
    blob: Vec<u8>,
    root_hash: Vec<u8>,
}

#[derive(Debug, Default)]
struct FailingOutput {
    cursor: Cursor<Vec<u8>>,
}

impl Write for FailingOutput {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected output failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailingOutput {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

#[derive(Debug, Default)]
struct InvalidInputOutput {
    cursor: Cursor<Vec<u8>>,
    wrote_once: bool,
}

impl Write for InvalidInputOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.wrote_once {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "injected output failure",
            ));
        }

        self.wrote_once = true;
        self.cursor.write(&buffer[..buffer.len().min(7)])
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for InvalidInputOutput {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.cursor.seek(position)
    }
}

#[derive(Debug, Default)]
struct FailingSeekOutput;

impl Write for FailingSeekOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailingSeekOutput {
    fn seek(&mut self, _position: io::SeekFrom) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected seek failure",
        ))
    }
}

#[derive(Debug, Default)]
struct FailingFinalSeekOutput {
    cursor: Cursor<Vec<u8>>,
    seeks: usize,
}

impl Write for FailingFinalSeekOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.cursor.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailingFinalSeekOutput {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.seeks += 1;
        if self.seeks == 2 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected final seek failure",
            ));
        }
        self.cursor.seek(position)
    }
}

#[derive(Debug, Default)]
struct FailingFlushOutput(Cursor<Vec<u8>>);

impl Write for FailingFlushOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected flush failure",
        ))
    }
}

impl Seek for FailingFlushOutput {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}

fn superblock(bytes: &[u8]) -> Verified {
    read_superblock(bytes).expect("a complete valid superblock block")
}

fn read_superblock<R: Read>(mut reader: R) -> io::Result<Verified> {
    let mut bytes = Unverified::default();
    reader.read_exact(bytes.as_mut())?;
    let superblock = Verified::try_from(bytes)?;
    let padding = superblock.padding();
    let copied = io::copy(&mut reader.take(padding), &mut io::sink())?;
    if copied != padding {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated verity superblock padding",
        ));
    }
    Ok(superblock)
}

fn write_superblock<W: Write>(superblock: &Verified, mut writer: W) -> io::Result<()> {
    let bytes = Unverified::from(superblock);
    writer.write_all(bytes.as_ref())?;
    io::copy(&mut io::repeat(0).take(superblock.padding()), &mut writer)?;
    Ok(())
}

fn start_tree<'a, W: Write + Seek + ?Sized>(
    superblock: &Verified,
    output: &'a mut W,
) -> TreeWriter<&'a mut W> {
    TreeWriter::new(output, superblock.clone()).unwrap()
}

fn compute(builder: &Format, data: &[u8]) -> Output {
    compute_in_chunks(builder, data, data.len().max(1))
}

fn compute_in_chunks(builder: &Format, data: &[u8], chunk_size: usize) -> Output {
    let mut blob = Cursor::new(Vec::new());
    let data_blocks = (data.len() as u64).div_ceil(u64::from(builder.data_block_size));
    let superblock = builder.build(data_blocks);
    write_superblock(&superblock, &mut blob).unwrap();
    let root_hash = {
        let mut tree = start_tree(&superblock, &mut blob);
        for chunk in data.chunks(chunk_size) {
            tree.write_all(chunk).unwrap();
        }
        tree.flush().unwrap();
        tree.digest().unwrap().to_vec()
    };
    Output {
        blob: blob.into_inner(),
        root_hash,
    }
}

#[test]
fn superblock_reads_back_what_was_written() {
    let salt: Vec<u8> = (0..24u8).collect(); // non-32 length, to test salt_size
    let uuid = [0x5Au8; 16];
    let format = Format::default().salt(&salt).uuid(uuid);
    let out = compute(&format, &vec![0u8; 16 * 1024]);
    let sb = superblock(&out.blob);
    assert_eq!(sb.hash_type(), HashType::Normal);
    assert_eq!(sb.uuid(), &uuid);
    assert_eq!(sb.algorithm(), Algorithm::Sha256);
    assert_eq!(sb.algorithm().as_ref(), "sha256");
    assert_eq!(sb.data_block_size(), 4096);
    assert_eq!(sb.hash_block_size(), 4096);
    assert_eq!(sb.data_blocks().get(), 4); // 16 KiB / 4 KiB
    assert_eq!(sb.salt().len(), salt.len());
    assert_eq!(sb.salt(), salt.as_slice());
}

#[test]
fn constructor_records_hash_configuration() {
    let sb = Format::default().hash_type(HashType::ChromeOs).build(1);

    assert_eq!(sb.hash_type(), HashType::ChromeOs);
    assert_eq!(sb.algorithm(), Algorithm::Sha256);
}

#[test]
fn verified_and_unverified_convert_through_standard_traits() {
    let verified = Format::default().build(1);
    let borrowed = Unverified::from(&verified);
    let owned = Unverified::from(verified.clone());

    assert_eq!(Verified::try_from(borrowed).unwrap(), verified);
    assert_eq!(Verified::try_from(owned).unwrap(), verified);
}

#[test]
fn unknown_algorithm_names_are_rejected_before_a_superblock_exists() {
    assert!("md5".parse::<Algorithm>().is_err());
    for alias in ["ripemd160", "whirlpool", "stribog256", "stribog512"] {
        assert!(alias.parse::<Algorithm>().is_err());
    }

    let mut bytes = Vec::new();
    write_superblock(&Format::default().build(1), &mut bytes).unwrap();
    bytes[32..35].copy_from_slice(b"md5");
    bytes[35..38].fill(0);
    let error = read_superblock(bytes.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn every_enabled_algorithm_works_with_the_minimum_hash_block_size() {
    let mut algorithms = Vec::new();
    #[cfg(feature = "sha1")]
    algorithms.push((Algorithm::Sha1, "sha1", 20));
    #[cfg(feature = "sha2")]
    algorithms.extend([
        (Algorithm::Sha224, "sha224", 28),
        (Algorithm::Sha256, "sha256", 32),
        (Algorithm::Sha384, "sha384", 48),
        (Algorithm::Sha512, "sha512", 64),
    ]);
    #[cfg(feature = "ripemd")]
    algorithms.push((Algorithm::Ripemd160, "rmd160", 20));
    #[cfg(feature = "whirlpool")]
    algorithms.push((Algorithm::Whirlpool, "wp512", 64));
    #[cfg(feature = "sha3")]
    algorithms.extend([
        (Algorithm::Sha3_224, "sha3-224", 28),
        (Algorithm::Sha3_256, "sha3-256", 32),
        (Algorithm::Sha3_384, "sha3-384", 48),
        (Algorithm::Sha3_512, "sha3-512", 64),
    ]);
    #[cfg(feature = "streebog")]
    algorithms.extend([
        (Algorithm::Streebog256, "streebog256", 32),
        (Algorithm::Streebog512, "streebog512", 64),
    ]);
    #[cfg(feature = "sm3")]
    algorithms.push((Algorithm::Sm3, "sm3", 32));
    #[cfg(feature = "blake2")]
    algorithms.extend([
        (Algorithm::Blake2b160, "blake2b-160", 20),
        (Algorithm::Blake2b256, "blake2b-256", 32),
        (Algorithm::Blake2b384, "blake2b-384", 48),
        (Algorithm::Blake2b512, "blake2b-512", 64),
        (Algorithm::Blake2s128, "blake2s-128", 16),
        (Algorithm::Blake2s160, "blake2s-160", 20),
        (Algorithm::Blake2s224, "blake2s-224", 28),
        (Algorithm::Blake2s256, "blake2s-256", 32),
    ]);

    for (algorithm, name, digest_size) in algorithms {
        assert_eq!(name.parse::<Algorithm>().unwrap(), algorithm);
        assert_eq!(algorithm.as_ref(), name);

        let format = Format::default().algorithm(algorithm).hash_block_size(512);
        let output = compute(&format, &vec![0xa5; 9 * 4096]);
        assert_eq!(output.root_hash.len(), digest_size, "{name}");
        assert_eq!(superblock(&output.blob).algorithm(), algorithm, "{name}");
    }
}

#[test]
fn superblock_binding_validates_closed_fields() {
    let zeros = [0u8; size_of::<Unverified>()];
    assert!(read_superblock(zeros.as_slice()).is_err());
    assert!(read_superblock([0u8; 100].as_slice()).is_err());

    let format = Format::default().salt([0u8; 32]);
    let valid = compute(&format, &[0u8; 4096]).blob;

    let mut bad_signature = valid.clone();
    bad_signature[0] ^= 1;
    assert!(read_superblock(bad_signature.as_slice()).is_err());

    let mut bad_version = valid.clone();
    bad_version[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert!(read_superblock(bad_version.as_slice()).is_err());

    let mut bad_hash_type = valid;
    bad_hash_type[12..16].copy_from_slice(&2u32.to_le_bytes());
    assert!(read_superblock(bad_hash_type.as_slice()).is_err());
}

#[test]
fn superblock_binding_accepts_both_defined_hash_types() {
    let format = Format::default().salt([0u8; 32]);
    let mut blob = compute(&format, &[0u8; 4096]).blob;
    blob[12..16].copy_from_slice(&0u32.to_le_bytes());

    let sb = superblock(&blob);
    assert_eq!(sb.hash_type(), HashType::ChromeOs);
    assert_eq!(sb.algorithm().as_ref(), "sha256");
    assert_eq!(sb.salt(), &[0u8; 32]);
}

#[test]
fn superblock_read_rejects_bad_algorithm_encoding() {
    let format = Format::default().salt([0u8; 32]);
    let mut algorithm = compute(&format, &[0u8; 4096]).blob;
    algorithm[32] = 0xff;
    let error = read_superblock(algorithm.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut algorithm = compute(&format, &[0u8; 4096]).blob;
    algorithm[39] = 1;
    let error = read_superblock(algorithm.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn superblock_read_rejects_an_oversized_wire_salt() {
    let format = Format::default().salt([0u8; 32]);
    let mut salt_size = compute(&format, &[0u8; 4096]).blob;
    salt_size[80..82].copy_from_slice(&257u16.to_le_bytes());
    let error = read_superblock(salt_size.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn superblock_read_rejects_noncanonical_field_padding() {
    let mut bytes = Vec::new();
    write_superblock(&Format::default().build(1), &mut bytes).unwrap();

    for offset in [82, 88, 344] {
        let mut malformed = bytes.clone();
        malformed[offset] = 1;
        let error = read_superblock(malformed.as_slice()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn superblock_read_ignores_outer_padding_contents() {
    let mut bytes = Vec::new();
    write_superblock(&Format::default().build(1), &mut bytes).unwrap();

    for offset in [size_of::<Unverified>(), 1024] {
        let mut modified = bytes.clone();
        modified[offset] = 1;
        read_superblock(modified.as_slice()).unwrap();
    }
}

#[test]
fn superblock_read_rejects_truncated_outer_padding() {
    let mut bytes = Vec::new();
    write_superblock(&Format::default().build(1), &mut bytes).unwrap();
    bytes.pop();

    let error = read_superblock(bytes.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn superblock_byte_layout() {
    let salt = vec![0u8; 32];
    let uuid = [0xABu8; 16];
    let format = Format::default().salt(&salt).uuid(uuid);
    // 16 KiB data → 4 data blocks.
    let data = vec![0u8; 16 * 1024];
    let out = compute(&format, &data);

    // Verified-superblock checks.
    assert_eq!(&out.blob[0..8], b"verity\0\0", "signature `verity\\0\\0`");
    assert_eq!(
        u32::from_le_bytes(out.blob[8..12].try_into().unwrap()),
        1,
        "version = 1"
    );
    assert_eq!(
        u32::from_le_bytes(out.blob[12..16].try_into().unwrap()),
        1,
        "hash_type = 1 (normal)"
    );
    assert_eq!(&out.blob[16..32], &uuid, "uuid bytes");
    // The algorithm name is NUL-padded to 32 bytes.
    assert_eq!(&out.blob[32..38], b"sha256", "algo prefix lowercase");
    assert!(
        out.blob[38..64].iter().all(|&b| b == 0),
        "algo NUL-padded to 32 bytes"
    );
    assert_eq!(
        u32::from_le_bytes(out.blob[64..68].try_into().unwrap()),
        4096,
        "data_block_size"
    );
    assert_eq!(
        u32::from_le_bytes(out.blob[68..72].try_into().unwrap()),
        4096,
        "hash_block_size"
    );
    // The data length is stored as a block count.
    assert_eq!(
        u64::from_le_bytes(out.blob[72..80].try_into().unwrap()),
        4u64,
        "data_blocks = data / data_block_size (in blocks)"
    );
    // The salt length excludes padding.
    assert_eq!(
        u16::from_le_bytes(out.blob[80..82].try_into().unwrap()),
        32u16,
        "salt_size = actual salt length"
    );
    // _pad1[6] zeroed.
    assert!(out.blob[82..88].iter().all(|&b| b == 0), "_pad1 zero");
    // salt[256]: first 32 bytes = salt, rest zero pad.
    assert_eq!(&out.blob[88..120], &salt[..], "salt bytes");
    assert!(
        out.blob[120..344].iter().all(|&b| b == 0),
        "salt zero-padded to 256"
    );
    // _pad2[168] zeroed.
    assert!(out.blob[344..512].iter().all(|&b| b == 0), "_pad2 zero");

    // The superblock is padded to the hash-block size.
    assert!(
        out.blob[512..4096].iter().all(|&b| b == 0),
        "superblock zero-padded to hash_block boundary"
    );
    // First hash block starts at offset 4096.
    assert!(out.blob.len() >= 4096 + 4096, "first hash block present");
}

#[test]
fn root_hash_deterministic_for_known_fixture() {
    let salt = vec![0u8; 32];
    let uuid = [0x5a; 16];
    let format = Format::default().salt(&salt).uuid(uuid);
    let data = vec![0u8; 16 * 1024];
    let a = compute(&format, &data);
    let b = compute(&format, &data);
    assert_eq!(a.blob, b.blob, "verity blob is deterministic");
    assert_eq!(a.root_hash, b.root_hash, "root_hash is deterministic");
}

#[test]
fn one_data_block_is_the_root_without_a_tree_level() {
    let salt = [0x5a; 32];
    let data = [0xa5; 4096];
    let format = Format::default().salt(salt);
    let output = compute(&format, &data);

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(data);
    assert_eq!(output.root_hash.as_slice(), hasher.finalize().as_slice());
    assert_eq!(output.blob.len(), 4096);
}

#[test]
fn hash_type_controls_salt_placement() {
    let salt = [0x5a; 32];
    let data = [0xa5; 4096];
    let format = Format::default().hash_type(HashType::ChromeOs).salt(salt);
    let output = compute(&format, &data);

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(salt);
    assert_eq!(output.root_hash.as_slice(), hasher.finalize().as_slice());
}

#[test]
fn chrome_os_uses_exact_digest_slots_with_power_of_two_fanout() {
    let salt = [0x5a; 32];
    let data = vec![0xa5; 17 * 4096];
    let format = Format::default()
        .hash_type(HashType::ChromeOs)
        .algorithm(Algorithm::Sha224)
        .hash_block_size(512)
        .salt(salt);
    let output = compute(&format, &data);

    let mut lower = [[0; 512]; 2];
    for (index, block) in data.chunks(4096).enumerate() {
        let mut hasher = Sha224::new();
        hasher.update(block);
        hasher.update(salt);
        let digest = hasher.finalize();
        let block = index / 16;
        let start = index % 16 * digest.len();
        lower[block][start..start + digest.len()].copy_from_slice(&digest);
    }

    let mut packed_root = [0; 512];
    for (index, block) in lower.iter().enumerate() {
        let mut hasher = Sha224::new();
        hasher.update(block);
        hasher.update(salt);
        let digest = hasher.finalize();
        let start = index * digest.len();
        packed_root[start..start + digest.len()].copy_from_slice(&digest);
    }
    let mut hasher = Sha224::new();
    hasher.update(packed_root);
    hasher.update(salt);
    assert_eq!(output.root_hash.as_slice(), hasher.finalize().as_slice());
    assert_eq!(output.blob.len(), 2048);
}

#[test]
fn salt_rejects_oversized_input() {
    let bytes: Vec<_> = (0u8..=250).cycle().take(257).collect();
    assert_eq!(
        Verified::builder().salt(&bytes).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn salt_setter_replaces_the_previous_value() {
    let superblock = Verified::builder()
        .salt(&[1, 2, 3, 4])
        .unwrap()
        .salt(&[5, 6])
        .unwrap()
        .build([0; 16], NonZeroU64::MIN)
        .unwrap();

    assert_eq!(superblock.salt(), &[5, 6]);
}

#[test]
fn builder_rejects_invalid_block_sizes() {
    for size in [0, 3, 96, 511, 513, 1024 * 1024] {
        assert_eq!(
            Verified::builder()
                .data_block_size(size)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            Verified::builder()
                .hash_block_size(size)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    for size in [512, 4096, 512 * 1024] {
        let superblock = Verified::builder()
            .data_block_size(size)
            .unwrap()
            .hash_block_size(size)
            .unwrap()
            .build([0; 16], NonZeroU64::MIN)
            .unwrap();
        assert_eq!(superblock.data_block_size(), size);
        assert_eq!(superblock.hash_block_size(), size);
    }
}

#[test]
fn tree_writer_rejects_input_beyond_the_declared_size() {
    let superblock = Format::default().salt([0u8; 32]).build(1);
    let mut output = Cursor::new(Vec::new());
    let mut tree = start_tree(&superblock, &mut output);
    let error = tree.write_all(&[0; 4097]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn tree_writer_reports_output_failure_before_accepting_more_input() {
    let superblock = Verified::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(17).unwrap())
        .unwrap();
    let mut tree = TreeWriter::new(FailingOutput::default(), superblock).unwrap();
    let block = [0; 512];

    // Sixteen SHA-256 slots fill the first 512-byte hash block. Each call
    // accepts one data block; emitting their hash block is deliberately
    // deferred until the next call, before that call consumes any input.
    for _ in 0..16 {
        assert_eq!(tree.write(&block).unwrap(), block.len());
    }
    assert_eq!(
        tree.write(&block).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );

    // A failed output may have performed a partial write, so the adapter is
    // poisoned instead of risking duplicated tree state on retry.
    assert_eq!(tree.write(&block).unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn an_invalid_input_output_error_still_poisons_the_writer() {
    let superblock = Verified::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(17).unwrap())
        .unwrap();
    let mut tree = TreeWriter::new(InvalidInputOutput::default(), superblock).unwrap();
    let block = [0; 512];

    for _ in 0..16 {
        tree.write_all(&block).unwrap();
    }
    assert_eq!(
        tree.write(&block).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(tree.write(&block).unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn a_seek_failure_poisons_the_writer() {
    let superblock = Format::default().build(1);
    let mut tree = TreeWriter::new(FailingSeekOutput, superblock).unwrap();

    assert_eq!(
        tree.write(&[0]).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(tree.write(&[0]).unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn a_final_seek_failure_poisons_the_writer() {
    let superblock = Format::default().build(1);
    let mut tree = TreeWriter::new(FailingFinalSeekOutput::default(), superblock).unwrap();
    tree.write_all(&[0; 4096]).unwrap();

    assert_eq!(tree.flush().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(tree.flush().unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn a_flush_failure_poisons_the_writer() {
    let superblock = Format::default().build(1);
    let mut tree = TreeWriter::new(FailingFlushOutput::default(), superblock).unwrap();
    tree.write_all(&[0; 4096]).unwrap();

    assert_eq!(tree.flush().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn digest_is_available_after_the_final_flush() {
    let superblock = Verified::builder()
        .data_block_size(512)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(2).unwrap())
        .unwrap();
    let mut output = Cursor::new(Vec::new());
    {
        let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
        tree.write_all(&[0; 1024]).unwrap();
        assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        tree.flush().unwrap();
        assert_eq!(tree.digest().unwrap().len(), 32);
    }
    assert_eq!(output.position(), 512);
    assert_eq!(output.into_inner().len(), 512);
}

#[test]
fn accepting_the_complete_final_block_seals_the_writer() {
    let superblock = Format::default().build(1);
    let mut output = Cursor::new(Vec::new());
    let mut tree = TreeWriter::new(&mut output, superblock).unwrap();

    tree.write_all(&[0; 4096]).unwrap();
    assert_eq!(
        tree.write(&[1]).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(tree.digest().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    tree.flush().unwrap();
    assert_eq!(tree.digest().unwrap().len(), 32);
}

#[test]
fn an_early_partial_flush_is_conventional_and_does_not_seal() {
    let superblock = Format::default().build(3);
    let mut output = Cursor::new(Vec::new());
    let mut tree = TreeWriter::new(&mut output, superblock).unwrap();

    tree.write_all(&[0; 4095]).unwrap();
    tree.flush().unwrap();
    assert_eq!(
        tree.digest().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    tree.write_all(&[0; 2 * 4096 + 1]).unwrap();
    tree.flush().unwrap();
    assert_eq!(tree.digest().unwrap().len(), 32);
    assert_eq!(
        tree.write(&[0]).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn an_intermediate_boundary_flush_preserves_the_tree_state() {
    let superblock = Format::default().build(17);
    let data = vec![0xa5; 17 * 4096];

    let mut direct_output = Cursor::new(Vec::new());
    let direct_digest = {
        let mut tree = TreeWriter::new(&mut direct_output, superblock.clone()).unwrap();
        tree.write_all(&data).unwrap();
        tree.flush().unwrap();
        tree.digest().unwrap().to_vec()
    };

    let mut flushed_output = Cursor::new(Vec::new());
    let flushed_digest = {
        let mut tree = TreeWriter::new(&mut flushed_output, superblock).unwrap();
        tree.write_all(&data[..4096]).unwrap();
        tree.flush().unwrap();
        assert_eq!(
            tree.digest().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        tree.write_all(&data[4096..]).unwrap();
        tree.flush().unwrap();
        tree.digest().unwrap().to_vec()
    };

    assert_eq!(flushed_output.into_inner(), direct_output.into_inner());
    assert_eq!(flushed_digest, direct_digest);
}

#[test]
fn superblock_constructor_rejects_an_overflowing_layout() {
    let error = Verified::builder()
        .build([0; 16], NonZeroU64::MAX)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn digest_rejects_input_that_ends_on_an_early_block_boundary() {
    let superblock = Format::default().salt([0u8; 32]).build(2);
    let mut output = Cursor::new(Vec::new());
    let mut tree = start_tree(&superblock, &mut output);
    tree.write_all(&[0; 4096]).unwrap();
    tree.flush().unwrap();
    let error = tree.digest().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn tree_writer_writes_only_tree_blocks() {
    let salt = [0u8; 32];
    let superblock = Format::default().salt(salt).build(100);
    let mut output = Cursor::new(Vec::new());
    let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
    tree.write_all(&vec![0; 100 * 4096]).unwrap();
    tree.flush().unwrap();
    tree.digest().unwrap();

    assert_eq!(output.into_inner().len(), 4096);
}

#[test]
fn superblock_read_rejects_invalid_tree_configuration() {
    let mut bytes = Vec::new();
    write_superblock(&Format::default().build(3), &mut bytes).unwrap();
    bytes[68..72].copy_from_slice(&64u32.to_le_bytes());
    let error = read_superblock(bytes.as_slice()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

// One hundred SHA-256 leaf hashes fit in one 4096-byte hash block. That block
// is the root level, so the root digest must cover every leaf hash in it.
#[test]
fn final_flush_matches_veritysetup_for_single_block_tree() {
    let salt = vec![0u8; 32];
    let format = Format::default().salt(&salt);
    let mut data = Vec::with_capacity(100 * 4096);
    for i in 0..100u32 {
        data.extend_from_slice(&vec![i as u8; 4096]);
    }
    let output = compute(&format, &data);

    // The output contains one superblock block and one root block.
    assert_eq!(
        output.blob.len(),
        8192,
        "single-block-tree blob must be exactly superblock + 1 hash block"
    );

    // A root block containing only the first leaf hash has a different digest.
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update(&salt);
    leaf_hasher.update(vec![0u8; 4096]); // first block (i=0, all zeros)
    let leaf_zero = leaf_hasher.finalize();
    let mut incomplete_root = vec![0u8; 4096];
    incomplete_root[..32].copy_from_slice(&leaf_zero);
    let mut incomplete_hasher = Sha256::new();
    incomplete_hasher.update(&salt);
    incomplete_hasher.update(&incomplete_root);
    let incomplete_digest = incomplete_hasher.finalize();

    assert_ne!(
        output.root_hash.as_slice(),
        &incomplete_digest[..],
        "root digest must cover more than the first leaf hash"
    );

    // Compute the digest of the complete packed root block.
    let mut packed_root = vec![0u8; 4096];
    for i in 0..100u32 {
        let mut h = Sha256::new();
        h.update(&salt);
        h.update(vec![i as u8; 4096]);
        let leaf = h.finalize();
        let off = (i as usize) * 32;
        packed_root[off..off + 32].copy_from_slice(&leaf);
    }
    let mut expected_hasher = Sha256::new();
    expected_hasher.update(&salt);
    expected_hasher.update(&packed_root);
    let expected_root = expected_hasher.finalize();
    assert_eq!(
        output.root_hash.as_slice(),
        &expected_root[..],
        "root_hash must equal SHA256(salt || all_100_leaf_hashes_packed_into_one_block)"
    );
}

#[test]
fn arbitrary_input_chunks_match_a_single_write_on_block_boundary() {
    let salt = vec![0u8; 32];
    let uuid = [0x5a; 16];
    let format = Format::default().salt(&salt).uuid(uuid);
    let data: Vec<u8> = (0u32..).map(|i| (i & 0xFF) as u8).take(16 * 1024).collect();
    let direct = compute(&format, &data);
    let streamed = compute_in_chunks(&format, &data, 777);
    assert_eq!(streamed.blob, direct.blob);
    assert_eq!(streamed.root_hash, direct.root_hash);
}

#[test]
fn arbitrary_fragments_match_a_single_write_for_complete_blocks() {
    let salt = vec![0u8; 32];
    let uuid = [0x5a; 16];
    let format = Format::default().salt(&salt).uuid(uuid);
    for &n in &[4096usize, 8192, 12288] {
        let data: Vec<u8> = (0u32..).map(|i| (i & 0xFF) as u8).take(n).collect();
        let direct = compute(&format, &data);
        let streamed = compute_in_chunks(&format, &data, 777);
        assert_eq!(streamed.blob, direct.blob, "blob mismatch at n={n}");
        assert_eq!(
            streamed.root_hash, direct.root_hash,
            "root_hash mismatch at n={n}"
        );
    }
}

#[test]
fn a_partial_final_block_is_not_implicitly_padded() {
    let superblock = Format::default().build(2);
    let mut output = Cursor::new(Vec::new());
    let mut tree = TreeWriter::new(&mut output, superblock).unwrap();
    tree.write_all(&vec![0xa5; 4097]).unwrap();
    tree.flush().unwrap();
    assert_eq!(
        tree.digest().unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    tree.write_all(&vec![0; 4095]).unwrap();
    tree.flush().unwrap();
    assert_eq!(tree.digest().unwrap().len(), 32);
}

#[test]
fn superblock_read_rejects_zero_data_blocks() {
    let valid = Format::default().build(1);
    let mut bytes = Unverified::from(valid);
    bytes.as_mut()[72..80].fill(0);
    assert_eq!(
        Verified::try_from(bytes).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn superblock_accepts_typical_block_sizes() {
    let _ = Format::default().salt([0u8; 32]).build(1);
}

#[test]
fn superblock_serializes_block_sizes() {
    let superblock = Verified::builder()
        .data_block_size(1024)
        .unwrap()
        .hash_block_size(512)
        .unwrap()
        .build([0; 16], NonZeroU64::new(7).unwrap())
        .unwrap();

    assert_eq!(superblock.data_block_size(), 1024);
    assert_eq!(superblock.hash_block_size(), 512);
}

#[test]
fn superblock_padding_reaches_the_hash_block_boundary() {
    assert_eq!(size_of::<Unverified>(), 512);
    for hash_block_size in [512, 4096, 8192, 16 * 1024] {
        let superblock = Verified::builder()
            .hash_block_size(hash_block_size)
            .unwrap()
            .build([0; 16], NonZeroU64::MIN)
            .unwrap();
        assert_eq!(
            superblock.padding(),
            u64::from(hash_block_size) - size_of::<Unverified>() as u64
        );
    }
}
