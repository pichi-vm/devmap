// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation)]

use std::io::{Cursor, Read, Seek, SeekFrom};

use devmap_snapshot::{ChunkSize, Layer, convert};

const SIZE: usize = 4096;

fn size() -> ChunkSize {
    ChunkSize::from_sectors(8).unwrap()
}

#[test]
fn conversion_is_sparse_and_round_trips() {
    let mut image = vec![0; 4 * SIZE];
    image[SIZE..2 * SIZE].fill(0x11);
    image[3 * SIZE..].fill(0x33);
    let mut cow = Cursor::new(Vec::new());
    let result = convert(&image[..], image.len() as u64, &mut cow, size()).unwrap();
    assert_eq!(result.exception_count, 2);
    assert_eq!(result.cow_bytes, cow.get_ref().len() as u64);

    let mut origin = Cursor::new(vec![0; image.len()]);
    let cow_bytes = cow.get_ref().len() as u64;
    let mut layer = Layer::open(&mut origin, &mut cow, image.len() as u64, cow_bytes).unwrap();
    let mut actual = Vec::new();
    layer.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, image);
}

#[test]
fn a_short_final_chunk_is_zero_padded() {
    let image = vec![0xa5; SIZE + 7];
    let mut cow = Cursor::new(Vec::new());
    convert(&image[..], image.len() as u64, &mut cow, size()).unwrap();
    let origin_bytes = 2 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; origin_bytes as usize]);
    let cow_bytes = cow.get_ref().len() as u64;
    let mut layer = Layer::open(&mut origin, &mut cow, origin_bytes, cow_bytes).unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64)).unwrap();
    let mut final_chunk = vec![0; SIZE];
    layer.read_exact(&mut final_chunk).unwrap();
    assert_eq!(&final_chunk[..7], &[0xa5; 7]);
    assert!(final_chunk[7..].iter().all(|byte| *byte == 0));
}

#[test]
fn input_length_is_an_exact_limit() {
    let image = vec![0x44; 2 * SIZE];
    let mut cow = Cursor::new(Vec::new());
    let result = convert(&image[..], SIZE as u64, &mut cow, size()).unwrap();
    assert_eq!(result.exception_count, 1);
}

#[test]
fn empty_input_still_creates_a_valid_store() {
    let mut cow = Cursor::new(Vec::new());
    let result = convert(&[][..], 0, &mut cow, size()).unwrap();
    assert_eq!(result.exception_count, 0);
    let mut origin = Cursor::new(Vec::<u8>::new());
    let cow_bytes = cow.get_ref().len() as u64;
    let layer = Layer::open(&mut origin, &mut cow, 0, cow_bytes).unwrap();
    assert_eq!(layer.len(), 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn sparse_and_sequential_conversion_match() {
    use std::io::Write as _;
    let mut file = tempfile::tempfile().unwrap();
    file.set_len((4 * SIZE) as u64).unwrap();
    file.seek(SeekFrom::Start((2 * SIZE) as u64)).unwrap();
    file.write_all(&vec![0x77; SIZE]).unwrap();
    let mut sparse = Cursor::new(Vec::new());
    let mut sequential = Cursor::new(Vec::new());
    devmap_snapshot::convert_sparse(&file, (4 * SIZE) as u64, &mut sparse, size()).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    convert(&mut file, (4 * SIZE) as u64, &mut sequential, size()).unwrap();
    assert_eq!(sparse.into_inner(), sequential.into_inner());
}
