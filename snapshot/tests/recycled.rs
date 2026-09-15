// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

use devmap_snapshot::{
    Layer,
    traits::std::{Create, Open, SyncData},
};

const SECTOR_SIZE: u64 = 512;

#[test]
fn create_over_a_dirty_store_hides_old_metadata() {
    let chunk_size_sectors = 8;
    let chunk = u64::from(chunk_size_sectors) * SECTOR_SIZE;
    let length = 8 * chunk;
    let cow_bytes = 11 * chunk;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = Cursor::new(vec![0xff; cow_bytes as usize]);
    {
        let mut layer = Layer::create(
            &mut origin,
            &mut cow,
            NonZeroU32::new(chunk_size_sectors).unwrap(),
        )
        .unwrap();
        layer.seek(SeekFrom::Start(3 * chunk)).unwrap();
        layer.write_all(&vec![0x33; chunk as usize]).unwrap();
        layer.sync_data().unwrap();
    }
    let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
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
fn open_discovers_the_chunk_size_from_the_header() {
    let chunk_size_sectors = 32u32;
    let chunk = u64::from(chunk_size_sectors) * SECTOR_SIZE;
    let cow_bytes = 4 * chunk;
    let mut origin = Cursor::new(vec![0; chunk as usize]);
    let mut cow = Cursor::new(vec![0; cow_bytes as usize]);
    Layer::create(
        &mut origin,
        &mut cow,
        NonZeroU32::new(chunk_size_sectors).unwrap(),
    )
    .unwrap()
    .sync_data()
    .unwrap();
    let mut opened = Layer::open(&mut origin, &mut cow).unwrap();
    opened.read_exact(&mut [0]).unwrap();
}
