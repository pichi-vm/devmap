// SPDX-License-Identifier: Apache-2.0

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use devmap_core::{
    BlockCount, BlockIo, ByteCursor, ReadBlocks, Region, Runtime, WriteBlocks, Zero,
};

#[test]
fn zero_reads_zeroes_and_discards_writes() {
    let mut blocks = Region::<_, 4>::new(Zero, 12, 2).unwrap();

    let mut block = [0xff; 4];
    blocks.read_block(1, &mut block).unwrap();
    assert_eq!(block, [0; 4]);

    blocks.write_block(0, &[1, 2, 3, 4]).unwrap();
    blocks.read_block(0, &mut block).unwrap();
    assert_eq!(block, [0; 4]);
    blocks.flush().unwrap();
}

#[test]
fn region_supplies_capacity_and_rejects_out_of_range_io() {
    let mut blocks = Region::<_, 4>::new(Zero, 10, 2).unwrap();
    assert_eq!(blocks.block_count(), 2);

    assert_eq!(
        blocks.read_block(2, &mut [0; 4]).unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        blocks.write_block(2, &[0; 4]).unwrap_err().kind(),
        std::io::ErrorKind::WriteZero
    );
    assert!(Region::<_, 4>::new(Zero, u64::MAX, 2).is_err());
}

#[test]
fn block_io_reads_and_writes_exact_blocks() {
    let mut storage = Cursor::new(vec![0, 1, 2, 3, 4, 5, 6, 7]);
    {
        let mut blocks = BlockIo::<_, 4>::new(&mut storage, 2).unwrap();
        let mut block = [0; 4];
        blocks.read_block(1, &mut block).unwrap();
        assert_eq!(block, [4, 5, 6, 7]);

        blocks.write_block(0, &[9, 8, 7, 6]).unwrap();
        assert_eq!(
            blocks.read_block(2, &mut block).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            blocks.write_block(2, &block).unwrap_err().kind(),
            std::io::ErrorKind::WriteZero
        );
    }
    assert_eq!(storage.into_inner(), [9, 8, 7, 6, 4, 5, 6, 7]);
}

#[test]
fn runtime_block_io_rejects_buffers_with_the_wrong_size() {
    let mut blocks = BlockIo::<_, 4>::new(Cursor::new(vec![0; 8]), 2).unwrap();

    assert_eq!(
        devmap_core::DynReadBlocks::read_block(&mut blocks, 0, &mut [0; 3])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        devmap_core::DynWriteBlocks::write_block(&mut blocks, 0, &[0; 5])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
fn runtime_adapts_any_const_sized_block_implementation() {
    let blocks = Region::<_, 4>::new(Zero, 0, 2).unwrap();
    let mut bytes = ByteCursor::new(Runtime::<_, 4>::new(blocks)).unwrap();

    let mut output = [1; 8];
    bytes.read_exact(&mut output).unwrap();
    assert_eq!(output, [0; 8]);
}

#[test]
fn block_io_reports_a_short_underlying_device() {
    let storage = Cursor::new(vec![0; 7]);
    let mut blocks = BlockIo::<_, 4>::new(storage, 2).unwrap();
    assert_eq!(
        blocks.read_block(1, &mut [0; 4]).unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn byte_cursor_reads_across_block_boundaries() {
    let storage = Cursor::new((0..12).collect::<Vec<_>>());
    let blocks = BlockIo::<_, 4>::new(storage, 3).unwrap();
    let mut bytes = ByteCursor::new(blocks).unwrap();

    bytes.seek(SeekFrom::Start(3)).unwrap();
    let mut output = [0; 7];
    bytes.read_exact(&mut output).unwrap();
    assert_eq!(output, [3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(bytes.stream_position().unwrap(), 10);
}

#[test]
fn byte_cursor_preserves_bytes_around_partial_writes() {
    let mut storage = Cursor::new((0..12).collect::<Vec<_>>());
    {
        let blocks = BlockIo::<_, 4>::new(&mut storage, 3).unwrap();
        let mut bytes = ByteCursor::new(blocks).unwrap();
        bytes.seek(SeekFrom::Start(3)).unwrap();
        bytes.write_all(&[20, 21, 22, 23, 24, 25]).unwrap();
        bytes.flush().unwrap();
    }
    assert_eq!(
        storage.into_inner(),
        [0, 1, 2, 20, 21, 22, 23, 24, 25, 9, 10, 11]
    );
}

#[test]
fn byte_cursor_has_fixed_length_semantics() {
    let mut storage = Cursor::new(vec![0; 8]);
    {
        let blocks = BlockIo::<_, 4>::new(&mut storage, 2).unwrap();
        let mut bytes = ByteCursor::new(blocks).unwrap();
        bytes.seek(SeekFrom::Start(7)).unwrap();
        assert_eq!(bytes.write(&[1, 2, 3]).unwrap(), 1);
        assert_eq!(bytes.write(&[2, 3]).unwrap(), 0);
        assert_eq!(bytes.read(&mut [0; 1]).unwrap(), 0);
    }
    assert_eq!(storage.into_inner(), [0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn constructors_reject_overflowing_geometry() {
    assert_eq!(
        BlockIo::<_, 4>::new(Cursor::new(Vec::<u8>::new()), u64::MAX)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}
