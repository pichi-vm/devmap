// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation)]

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;

use devmap_snapshot::{
    Layer,
    traits::std::{Compact, Create, Geometry, Merge, Open, Readable, Scale, SyncData, Writable},
};

const SIZE: usize = 4096;
const CHUNK_SIZE_SECTORS: u32 = 8;
const CHUNK_SIZE: NonZeroU32 = NonZeroU32::new(CHUNK_SIZE_SECTORS).unwrap();
const PER_AREA: u64 = SIZE as u64 / 16;

fn store(origin_chunks: u64) -> Cursor<Vec<u8>> {
    let areas = origin_chunks.div_ceil(PER_AREA).max(1);
    let sentinel = u64::from(origin_chunks > 0 && origin_chunks % PER_AREA == 0);
    let chunks = 1 + areas + origin_chunks + sentinel;
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
fn operations_require_only_the_capabilities_they_use() {
    fn create<O, C>(origin: O, cow: C) -> std::io::Result<Layer<O, C>>
    where
        O: Geometry,
        C: Write + Seek + Geometry + SyncData,
    {
        Layer::create(origin, cow, CHUNK_SIZE)
    }

    fn open<O, C>(origin: O, cow: C) -> std::io::Result<Layer<O, C>>
    where
        O: Geometry,
        C: Read + Seek + Geometry,
    {
        Layer::open(origin, cow)
    }

    fn persist<O, C: Write + Seek + SyncData>(layer: &mut Layer<O, C>) {
        SyncData::sync_data(layer).unwrap();
    }

    fn merge<O: Write + Seek + SyncData, C: Read + Write + Seek + SyncData>(
        layer: &mut Layer<O, C>,
    ) {
        layer.merge().unwrap();
    }

    fn compact<O: Read + Seek, C: Read + Seek>(layer: &mut Layer<O, C>) {
        layer.compact(std::io::sink()).unwrap();
    }

    let _ = (
        create::<Cursor<Vec<u8>>, Cursor<Vec<u8>>>,
        open::<Cursor<Vec<u8>>, Cursor<Vec<u8>>>,
        persist::<Cursor<Vec<u8>>, Cursor<Vec<u8>>>,
        merge::<Cursor<Vec<u8>>, Cursor<Vec<u8>>>,
        compact::<Cursor<Vec<u8>>, Cursor<Vec<u8>>>,
    );
}

#[test]
fn chunk_sizes_cover_the_kernel_range() {
    let origin = Cursor::new(Vec::<u8>::new());
    let cow = Cursor::new(vec![0; 8 * SIZE]);
    assert!(Layer::create(origin, cow, NonZeroU32::new(32).unwrap()).is_ok());

    let origin = Cursor::new(Vec::<u8>::new());
    let cow = Cursor::new(vec![0; 2 * SIZE]);
    assert!(Layer::create(origin, cow, NonZeroU32::new(9).unwrap()).is_err());

    let origin = Cursor::new(Vec::<u8>::new());
    let cow = Cursor::new(vec![0; 2 * SIZE]);
    assert!(Layer::create(origin, cow, NonZeroU32::new(4).unwrap()).is_ok());

    let origin = Cursor::new(Vec::<u8>::new());
    let cow = Cursor::new(vec![0; 2 * SIZE]);
    assert!(Layer::create(origin, cow, NonZeroU32::new(8).unwrap()).is_ok());

    let origin = Cursor::new(Vec::<u8>::new());
    let cow = Cursor::new(Vec::<u8>::new());
    assert!(Layer::create(origin, cow, NonZeroU32::new(1 << 22).unwrap()).is_err());
}

#[test]
fn explicit_chunk_size_must_match_both_endpoint_block_sizes() {
    let origin = Cursor::new(vec![0; 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let cow = Cursor::new(vec![0; 2 * 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let error = Layer::create(origin, cow, NonZeroU32::new(8).unwrap())
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn compatible_chunk_size_accepts_endpoint_block_sizes() {
    let mut origin = Cursor::new(vec![0; 65_536]);
    let mut cow = Cursor::new(vec![0; 2 * 65_536]);
    let origin = (&mut origin)
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let cow_device = (&mut cow).scale(NonZeroU32::new(65_536).unwrap()).unwrap();
    let layer = Layer::create(origin, cow_device, NonZeroU32::new(128).unwrap()).unwrap();
    drop(layer);

    assert_eq!(
        u32::from_le_bytes(cow.get_ref()[12..16].try_into().unwrap()),
        128
    );
}

#[test]
fn layer_geometry_is_aligned_to_both_endpoints() {
    let origin = Cursor::new(vec![0; 2 * 65_536])
        .scale(NonZeroU32::new(4096).unwrap())
        .unwrap();
    let cow = Cursor::new(vec![0; 2 * 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let mut layer = Layer::create(origin, cow, NonZeroU32::new(128).unwrap()).unwrap();
    assert_eq!(layer.block_size().unwrap().get(), 65_536);
    assert_eq!(layer.count().unwrap(), 2);

    let origin = Cursor::new(vec![0; 4096])
        .scale(NonZeroU32::new(4096).unwrap())
        .unwrap();
    let cow = Cursor::new(vec![0; 2 * 65_536])
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let error = Layer::create(origin, cow, NonZeroU32::new(128).unwrap())
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn a_layer_is_a_seekable_byte_stream() {
    let bytes = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0x77; bytes as usize]);
    let mut cow = store(4);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        layer.seek(SeekFrom::Start(SIZE as u64 + 37)).unwrap();
        layer.write_all(&[1, 2, 3, 4]).unwrap();
        layer.sync_data().unwrap();
    }
    let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 + 35)).unwrap();
    let mut bytes = [0; 8];
    layer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [0x77, 0x77, 1, 2, 3, 4, 0x77, 0x77]);
}

#[test]
fn writes_cross_chunk_boundaries_through_write_all() {
    let length = 3 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(3);
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 - 2)).unwrap();
    layer.write_all(&[1, 2, 3, 4, 5]).unwrap();
    layer.sync_data().unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 - 2)).unwrap();
    let mut read = [0; 5];
    layer.read_exact(&mut read).unwrap();
    assert_eq!(read, [1, 2, 3, 4, 5]);
}

#[test]
fn reopening_recovers_and_appends() {
    let length = 8 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(8);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        write_chunk(&mut layer, 1, 0xa1);
        write_chunk(&mut layer, 4, 0xa4);
        layer.sync_data().unwrap();
    }
    {
        let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
        write_chunk(&mut layer, 6, 0xa6);
        layer.sync_data().unwrap();
    }
    let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
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
    let mut lower = Layer::create(&mut origin, &mut lower_cow, CHUNK_SIZE).unwrap();
    write_chunk(&mut lower, 0, 0x11);
    let mut upper = Layer::create(lower, &mut upper_cow, CHUNK_SIZE).unwrap();
    write_chunk(&mut upper, 1, 0x22);
    upper.sync_data().unwrap();
    assert!(read_chunk(&mut upper, 0).iter().all(|byte| *byte == 0x11));
    assert!(read_chunk(&mut upper, 1).iter().all(|byte| *byte == 0x22));
}

#[test]
fn layers_nest_to_runtime_depth_through_an_erased_source() {
    let length = 4 * SIZE as u64;
    let mut lower: Box<dyn Readable> = Box::new(Cursor::new(vec![0; length as usize]));

    for (index, byte) in [(0, 0x11), (1, 0x22), (2, 0x33)] {
        let mut layer = Layer::create(lower, store(4), CHUNK_SIZE).unwrap();
        write_chunk(&mut layer, index, byte);
        lower = Box::new(layer);
    }

    for (index, byte) in [(0, 0x11), (1, 0x22), (2, 0x33)] {
        lower.seek(SeekFrom::Start(index * SIZE as u64)).unwrap();
        let mut contents = vec![0; SIZE];
        lower.read_exact(&mut contents).unwrap();
        assert!(contents.iter().all(|value| *value == byte));
    }
}

#[test]
fn an_erased_lower_layer_can_receive_a_merge() {
    let length = 4 * SIZE as u64;
    let mut lower =
        Layer::create(Cursor::new(vec![0; length as usize]), store(4), CHUNK_SIZE).unwrap();
    write_chunk(&mut lower, 0, 0x11);
    let lower: Box<dyn Writable> = Box::new(lower);

    let mut upper = Layer::create(lower, store(4), CHUNK_SIZE).unwrap();
    write_chunk(&mut upper, 1, 0x22);
    upper.merge().unwrap();

    assert!(read_chunk(&mut upper, 0).iter().all(|byte| *byte == 0x11));
    assert!(read_chunk(&mut upper, 1).iter().all(|byte| *byte == 0x22));
}

#[test]
fn read_only_endpoints_can_be_opened_and_compacted() {
    let length = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(4);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        write_chunk(&mut layer, 1, 0x5a);
        layer.sync_data().unwrap();
    }

    let origin: Box<dyn Readable> = Box::new(origin);
    let cow: Box<dyn Readable> = Box::new(cow);
    let mut layer = Layer::open(origin, cow).unwrap();

    assert!(read_chunk(&mut layer, 1).iter().all(|byte| *byte == 0x5a));
    let mut compact = Vec::new();
    layer.compact(&mut compact).unwrap();
    assert_eq!(compact.len(), 3 * SIZE);
}

#[test]
fn a_full_metadata_area_has_a_zero_sentinel() {
    let length = PER_AREA * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(PER_AREA);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
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
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        write_chunk(&mut layer, 2, 0xcc);
        layer.sync_data().unwrap();
    }
    let mut layer = Layer::open(&mut origin, &mut cow).unwrap();
    layer.merge().unwrap();
    assert!(read_chunk(&mut layer, 2).iter().all(|byte| *byte == 0xcc));
    drop(layer);
    assert!(
        origin.get_ref()[2 * SIZE..3 * SIZE]
            .iter()
            .all(|byte| *byte == 0xcc)
    );
    let mut reopened = Layer::open(&mut origin, &mut cow).unwrap();
    assert!(
        read_chunk(&mut reopened, 2)
            .iter()
            .all(|byte| *byte == 0xcc)
    );
}

#[test]
fn compact_writes_only_exceptions_that_differ_from_the_origin() {
    let length = 4 * SIZE as u64;
    let mut origin = Cursor::new(vec![0x11; length as usize]);
    let mut cow = store(4);
    let mut compact = Vec::new();
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        write_chunk(&mut layer, 0, 0xaa);
        write_chunk(&mut layer, 0, 0x11);
        write_chunk(&mut layer, 2, 0xcc);
        layer.compact(&mut compact).unwrap();

        assert!(read_chunk(&mut layer, 0).iter().all(|byte| *byte == 0x11));
        assert!(read_chunk(&mut layer, 2).iter().all(|byte| *byte == 0xcc));
    }

    assert_eq!(compact.len(), 3 * SIZE);
    let mut compact = Cursor::new(compact);
    let mut layer = Layer::open(&mut origin, &mut compact).unwrap();
    assert!(read_chunk(&mut layer, 0).iter().all(|byte| *byte == 0x11));
    assert!(read_chunk(&mut layer, 2).iter().all(|byte| *byte == 0xcc));
}

#[test]
fn compact_terminates_a_full_metadata_area() {
    let length = PER_AREA * SIZE as u64;
    let mut origin = Cursor::new(vec![0; length as usize]);
    let mut cow = store(PER_AREA);
    let mut compact = Vec::new();
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    for index in 0..PER_AREA {
        write_chunk(&mut layer, index, 0x5a);
    }
    layer.compact(&mut compact).unwrap();

    assert_eq!(compact.len(), (PER_AREA as usize + 3) * SIZE);
    assert!(
        compact[compact.len() - SIZE..]
            .iter()
            .all(|byte| *byte == 0)
    );
}
