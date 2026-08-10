// SPDX-License-Identifier: Apache-2.0

//! Cross-validation of the superblock writer against a real
//! `dmzadm --format` superblock.
//!
//! The fixture is the first 512 bytes of the primary superblock `dmzadm`
//! wrote to a `null_blk` zoned device (256 MiB, 4 MiB zones, 8
//! conventional zones). Its tail out to 4 KiB is all zero — confirmed
//! when captured — so the full block is the fixture followed by zeroes.
//!
//! This is the load-bearing correctness check: it proves the non-standard
//! `crc32_le` and the field offsets reproduce dm-zoned's bytes exactly.

use devmap_zoned::{BLOCK_SIZE, Superblock, crc32_le};

/// The captured 512-byte `dmz_super` struct.
const FIXTURE: &[u8; 512] = include_bytes!("fixtures/dmzadm_super_v2.bin");

/// The full 4 KiB block dmzadm's CRC covers: the struct plus zero padding.
fn fixture_block() -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    block[..512].copy_from_slice(FIXTURE);
    block
}

#[test]
fn crc32_le_reproduces_the_stored_superblock_crc() {
    let block = fixture_block();
    let stored = u32::from_le_bytes(block[44..48].try_into().unwrap());
    assert_eq!(stored, 0xf4a5_1605, "the captured fixture's stored CRC");

    // Recompute the way the kernel does: zero the CRC field, seed with the
    // generation (1 for a fresh format), hash the whole 4 KiB block.
    let generation = u64::from_le_bytes(block[8..16].try_into().unwrap());
    assert_eq!(generation, 1);
    let mut zeroed = block;
    zeroed[44..48].fill(0);
    assert_eq!(crc32_le(generation as u32, &zeroed), stored);
}

#[test]
fn from_block_parses_the_real_superblock() {
    let sb = Superblock::from_block(&fixture_block()).expect("real dmzadm SB must parse");
    assert_eq!(sb.version, 2);
    assert_eq!(sb.generation, 1);
    assert_eq!(sb.sb_block, 0);
    // 256 MiB / 4 MiB = 64 zones, 8 conventional; the metadata occupies
    // one zone each for primary and secondary, and dmzadm reserved 7
    // sequential zones, leaving 64 - 2 - 7 = 55 data chunks.
    assert_eq!(sb.nr_chunks, 55);
    assert_eq!(sb.nr_map_blocks, 1);
    assert_eq!(sb.nr_bitmap_blocks, 64);
    assert_eq!(
        sb.nr_meta_blocks,
        1 + sb.nr_map_blocks + sb.nr_bitmap_blocks
    );
    assert_eq!(sb.nr_reserved_seq, 7);
    assert!(sb.label.starts_with(b"dmz-dmztest"));
}

#[test]
fn to_block_round_trips_the_real_superblock_byte_for_byte() {
    // Parse the real superblock, re-serialise it, and require the first
    // 512 bytes to come back identical — the writer's offsets and CRC must
    // match dmzadm's, random UUIDs and all.
    let sb = Superblock::from_block(&fixture_block()).expect("parse");
    let rebuilt = sb.to_block();
    assert_eq!(
        &rebuilt[..512],
        &FIXTURE[..],
        "re-serialised superblock must equal dmzadm's bytes"
    );
    // And the CRC dmzadm stored must sit at offset 44 of our output.
    assert_eq!(&rebuilt[44..48], &FIXTURE[44..48]);
}

#[test]
fn from_block_rejects_a_corrupted_crc() {
    let mut block = fixture_block();
    block[100] ^= 0xff; // flip a byte the CRC covers
    assert_eq!(
        Superblock::from_block(&block),
        Err(devmap_zoned::ParseError::BadCrc)
    );
}

#[test]
fn from_block_rejects_a_foreign_block() {
    let block = [0u8; BLOCK_SIZE];
    assert_eq!(
        Superblock::from_block(&block),
        Err(devmap_zoned::ParseError::BadMagic)
    );
}
