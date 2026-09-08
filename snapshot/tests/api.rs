// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use devmap_snapshot::{ChunkSize, Layer, SyncData};

const SIZE: usize = 4096;
const PER_AREA: u64 = SIZE as u64 / 16;

fn chunk_size() -> ChunkSize {
    ChunkSize::from_sectors(8).unwrap()
}

fn store(origin_chunks: u64) -> Cursor<Vec<u8>> {
    let chunks = chunk_size().cow_chunks(origin_chunks).unwrap();
    Cursor::new(vec![0; usize::try_from(chunks).unwrap() * SIZE])
}

fn write_chunk<O, C>(layer: &mut Layer<O, C>, index: u64, byte: u8)
where
    O: Read + Seek,
    C: Read + Write + Seek + SyncData,
{
    layer.seek(SeekFrom::Start(index * SIZE as u64)).unwrap();
    layer.write_all(&vec![byte; SIZE]).unwrap();
}

fn read_chunk<O: Read + Seek, C: Read + Seek>(layer: &mut Layer<O, C>, index: u64) -> Vec<u8> {
    layer.seek(SeekFrom::Start(index * SIZE as u64)).unwrap();
    let mut bytes = vec![0; SIZE];
    layer.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn chunk_sizes_cover_the_kernel_range() {
    assert!(ChunkSize::from_sectors(0).is_err());
    assert!(ChunkSize::from_sectors(9).is_err());
    assert!(ChunkSize::from_sectors(8).is_ok());
    assert!(ChunkSize::from_sectors(1 << 21).is_ok());
}

#[test]
fn a_layer_is_a_seekable_byte_stream() {
    let bytes = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0x77; bytes as usize]);
    let mut cow = store(4);
    {
        let cow_bytes = cow.get_ref().len() as u64;
        let mut layer =
            Layer::create(&mut origin, &mut cow, bytes, cow_bytes, chunk_size()).unwrap();
        layer.seek(SeekFrom::Start(SIZE as u64 + 37)).unwrap();
        layer.write_all(&[1, 2, 3, 4]).unwrap();
        layer.sync_data().unwrap();
        assert_eq!(layer.exception_count(), Some(1));
    }
    let cow_bytes = cow.get_ref().len() as u64;
    let mut layer = Layer::open(&mut origin, &mut cow, bytes, cow_bytes).unwrap();
    assert_eq!(layer.chunk_size(), None);
    layer.seek(SeekFrom::Start(SIZE as u64 + 35)).unwrap();
    let mut bytes = [0; 8];
    layer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0x77, 0x77, 1, 2, 3, 4, 0x77, 0x77]);
    assert_eq!(layer.chunk_size(), Some(chunk_size()));
}

#[test]
fn writes_cross_chunk_boundaries_through_write_all() {
    let length = 3 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(3);
    let cow_bytes = cow.get_ref().len() as u64;
    let mut layer = Layer::create(&mut origin, &mut cow, length, cow_bytes, chunk_size()).unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 - 2)).unwrap();
    layer.write_all(&[1, 2, 3, 4, 5]).unwrap();
    layer.sync_data().unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 - 2)).unwrap();
    let mut read = [0; 5];
    layer.read_exact(&mut read).unwrap();
    assert_eq!(read, [1, 2, 3, 4, 5]);
    assert_eq!(layer.exception_count(), Some(2));
}

#[test]
fn reopening_recovers_and_appends() {
    let length = 8 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(8);
    {
        let cow_bytes = cow.get_ref().len() as u64;
        let mut layer =
            Layer::create(&mut origin, &mut cow, length, cow_bytes, chunk_size()).unwrap();
        write_chunk(&mut layer, 1, 0xa1);
        write_chunk(&mut layer, 4, 0xa4);
        layer.sync_data().unwrap();
    }
    {
        let cow_bytes = cow.get_ref().len() as u64;
        let mut layer = Layer::open(&mut origin, &mut cow, length, cow_bytes).unwrap();
        write_chunk(&mut layer, 6, 0xa6);
        layer.sync_data().unwrap();
    }
    let cow_bytes = cow.get_ref().len() as u64;
    let mut layer = Layer::open(&mut origin, &mut cow, length, cow_bytes).unwrap();
    for (index, byte) in [(1, 0xa1), (4, 0xa4), (6, 0xa6)] {
        assert!(
            read_chunk(&mut layer, index)
                .iter()
                .all(|value| *value == byte)
        );
    }
}

#[test]
fn layers_nest_through_standard_traits() {
    let length = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut lower_cow = store(4);
    let mut upper_cow = store(4);
    let lower_bytes = lower_cow.get_ref().len() as u64;
    let upper_bytes = upper_cow.get_ref().len() as u64;
    let mut lower = Layer::create(
        &mut origin,
        &mut lower_cow,
        length,
        lower_bytes,
        chunk_size(),
    )
    .unwrap();
    write_chunk(&mut lower, 0, 0x11);
    let mut upper =
        Layer::create(lower, &mut upper_cow, length, upper_bytes, chunk_size()).unwrap();
    write_chunk(&mut upper, 1, 0x22);
    upper.sync_data().unwrap();
    assert!(read_chunk(&mut upper, 0).iter().all(|byte| *byte == 0x11));
    assert!(read_chunk(&mut upper, 1).iter().all(|byte| *byte == 0x22));
}

#[test]
fn a_full_metadata_area_has_a_zero_sentinel() {
    let length = PER_AREA * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(PER_AREA);
    {
        let cow_bytes = cow.get_ref().len() as u64;
        let mut layer =
            Layer::create(&mut origin, &mut cow, length, cow_bytes, chunk_size()).unwrap();
        for index in 0..PER_AREA {
            write_chunk(&mut layer, index, 0x5a);
        }
        layer.sync_data().unwrap();
    }
    let sentinel = usize::try_from(1 + PER_AREA + 1).unwrap() * SIZE;
    assert!(
        cow.get_ref()[sentinel..sentinel + SIZE]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn merge_persists_origin_then_empties_store() {
    let length = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(4);
    {
        let cow_bytes = cow.get_ref().len() as u64;
        let mut layer =
            Layer::create(&mut origin, &mut cow, length, cow_bytes, chunk_size()).unwrap();
        write_chunk(&mut layer, 2, 0xcc);
        layer.sync_data().unwrap();
    }
    let cow_bytes = cow.get_ref().len() as u64;
    let layer = Layer::open(&mut origin, &mut cow, length, cow_bytes).unwrap();
    layer.merge().run().unwrap();
    assert!(
        origin.get_ref()[2 * SIZE..3 * SIZE]
            .iter()
            .all(|byte| *byte == 0xcc)
    );
    let cow_bytes = cow.get_ref().len() as u64;
    let mut reopened = Layer::open(&mut origin, &mut cow, length, cow_bytes).unwrap();
    assert!(
        read_chunk(&mut reopened, 2)
            .iter()
            .all(|byte| *byte == 0xcc)
    );
    assert_eq!(reopened.exception_count(), Some(0));
}
