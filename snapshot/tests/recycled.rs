// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use devmap_snapshot::{ChunkSize, Layer, SyncData};

#[test]
fn create_over_a_dirty_store_hides_old_metadata() {
    let size = ChunkSize::from_sectors(8).unwrap();
    let chunk = size.bytes().get();
    let length = 8 * chunk;
    let cow_bytes = size.cow_chunks(8).unwrap() * chunk;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = Cursor::new(vec![0xff; cow_bytes as usize]);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, length, cow_bytes, size).unwrap();
        layer.seek(SeekFrom::Start(3 * chunk)).unwrap();
        layer.write_all(&vec![0x33; chunk as usize]).unwrap();
        layer.sync_data().unwrap();
    }
    let mut layer = Layer::open(&mut origin, &mut cow, length, cow_bytes).unwrap();
    let mut image = Vec::new();
    layer.read_to_end(&mut image).unwrap();
    assert!(image[..3 * chunk as usize].iter().all(|byte| *byte == 0));
    assert!(
        image[3 * chunk as usize..4 * chunk as usize]
            .iter()
            .all(|byte| *byte == 0x33)
    );
    assert!(image[4 * chunk as usize..].iter().all(|byte| *byte == 0));
}

#[test]
fn chunk_size_is_discovered_at_runtime() {
    let size = ChunkSize::DEFAULT;
    let chunk = size.bytes().get();
    let cow_bytes = size.cow_chunks(1).unwrap() * chunk;
    let mut origin = Cursor::new(vec![0; chunk as usize]);
    let mut cow = Cursor::new(vec![0; cow_bytes as usize]);
    Layer::create(&mut origin, &mut cow, chunk, cow_bytes, size)
        .unwrap()
        .sync_data()
        .unwrap();
    let mut opened = Layer::open(&mut origin, &mut cow, chunk, cow_bytes).unwrap();
    assert_eq!(opened.chunk_size(), None);
    opened.read_exact(&mut [0]).unwrap();
    assert_eq!(opened.chunk_size(), Some(size));
}
