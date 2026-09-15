// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::type_complexity)]

use std::cell::RefCell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;
use std::rc::Rc;

use devmap_snapshot::{
    Layer,
    traits::std::{Create, Geometry, Merge, Open, Scale, SyncData},
};

const SIZE: usize = 4096;
const CHUNK_SIZE_SECTORS: u32 = 8;
const CHUNK_SIZE: NonZeroU32 = NonZeroU32::new(CHUNK_SIZE_SECTORS).unwrap();

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Write { at: u64, len: usize },
    Flush,
    SyncData,
}

struct Logged {
    inner: Cursor<Vec<u8>>,
    events: Rc<RefCell<Vec<Event>>>,
    writes: usize,
    fail_at: Option<usize>,
    syncs: usize,
    fail_sync_at: Option<usize>,
}

impl Read for Logged {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}

impl Write for Logged {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_at == Some(self.writes) {
            return Err(io::Error::other("injected write failure"));
        }
        self.writes += 1;
        self.events.borrow_mut().push(Event::Write {
            at: self.inner.position(),
            len: bytes.len(),
        });
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.events.borrow_mut().push(Event::Flush);
        Ok(())
    }
}

impl Seek for Logged {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        self.inner.seek(seek)
    }
}

impl SyncData for Logged {
    fn sync_data(&mut self) -> io::Result<()> {
        self.events.borrow_mut().push(Event::SyncData);
        if self.fail_sync_at == Some(self.syncs) {
            return Err(io::Error::other("injected persistence failure"));
        }
        self.syncs += 1;
        Ok(())
    }
}

impl Geometry for Logged {
    fn block_size(&self) -> io::Result<NonZeroU32> {
        Ok(NonZeroU32::MIN)
    }

    fn count(&mut self) -> io::Result<u64> {
        self.inner.count()
    }
}

fn setup() -> (Cursor<Vec<u8>>, Logged, Rc<RefCell<Vec<Event>>>) {
    let origin_chunks = 4;
    let cow_bytes = (origin_chunks + 3) * SIZE as u64;
    let events = Rc::new(RefCell::new(Vec::new()));
    (
        Cursor::new(vec![0; origin_chunks as usize * SIZE]),
        Logged {
            inner: Cursor::new(vec![0; cow_bytes as usize]),
            events: events.clone(),
            writes: 0,
            fail_at: None,
            syncs: 0,
            fail_sync_at: None,
        },
        events,
    )
}

#[test]
fn flush_orders_data_before_pointer_without_claiming_pointer_durability() {
    let (mut origin, mut cow, events) = setup();
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    layer.write_all(&vec![0xaa; SIZE]).unwrap();
    events.borrow_mut().clear();
    layer.flush().unwrap();
    assert_eq!(
        *events.borrow(),
        [
            Event::SyncData,
            Event::Write {
                at: SIZE as u64,
                len: SIZE
            },
            Event::Flush,
        ]
    );

    events.borrow_mut().clear();
    layer.flush().unwrap();
    assert_eq!(*events.borrow(), [Event::Flush]);
}

#[test]
fn sync_data_adds_the_completion_persistence_barrier() {
    let (mut origin, mut cow, events) = setup();
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    layer.write_all(&vec![0xaa; SIZE]).unwrap();
    events.borrow_mut().clear();
    layer.sync_data().unwrap();
    assert_eq!(events.borrow().last(), Some(&Event::SyncData));
    assert_eq!(
        events
            .borrow()
            .iter()
            .filter(|event| **event == Event::SyncData)
            .count(),
        2
    );
}

#[test]
fn writes_matching_a_lower_chunk_do_not_promote_it() {
    let (mut origin, mut cow, events) = setup();
    origin.get_mut()[..SIZE].fill(0x55);
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    events.borrow_mut().clear();

    layer.write_all(&vec![0x55; SIZE]).unwrap();
    layer.seek(SeekFrom::Start(SIZE as u64 + 7)).unwrap();
    layer.write_all(&[0; 19]).unwrap();

    assert!(events.borrow().is_empty());
    layer.flush().unwrap();
    assert_eq!(*events.borrow(), [Event::Flush]);
}

#[test]
fn a_skipped_promotion_needs_no_cow_capacity() {
    let origin = devmap_zero::Zero::new((2 * SIZE + 17) as u64);
    let mut cow = Cursor::new(vec![0; 2 * SIZE]);
    let mut layer = Layer::create(origin, &mut cow, CHUNK_SIZE).unwrap();

    layer.write_all(&vec![0; 2 * SIZE + 17]).unwrap();
    assert_eq!(layer.stream_position().unwrap(), (2 * SIZE + 17) as u64);
    layer.seek(SeekFrom::Start(0)).unwrap();
    let error = layer.write_all(&vec![1; SIZE]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    layer.write_all(&vec![0; SIZE]).unwrap();
    layer.sync_data().unwrap();
    drop(layer);
    assert!(cow.get_ref()[SIZE..].iter().all(|byte| *byte == 0));
}

#[test]
fn an_existing_exception_is_written_unconditionally() {
    let (mut origin, mut cow, events) = setup();
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    events.borrow_mut().clear();

    layer.write_all(&vec![0xaa; SIZE]).unwrap();
    assert_eq!(
        *events.borrow(),
        [Event::Write {
            at: 2 * SIZE as u64,
            len: SIZE,
        }]
    );

    events.borrow_mut().clear();
    layer.seek(SeekFrom::Start(0)).unwrap();
    layer.write_all(&vec![0xaa; SIZE]).unwrap();
    assert_eq!(
        *events.borrow(),
        [Event::Write {
            at: 2 * SIZE as u64,
            len: SIZE,
        }]
    );

    events.borrow_mut().clear();
    layer.seek(SeekFrom::Start(0)).unwrap();
    layer.write_all(&vec![0; SIZE]).unwrap();
    assert_eq!(
        *events.borrow(),
        [Event::Write {
            at: 2 * SIZE as u64,
            len: SIZE,
        }]
    );
    layer.sync_data().unwrap();
    drop(layer);
    assert_eq!(
        u64::from_le_bytes(cow.inner.get_ref()[SIZE + 8..SIZE + 16].try_into().unwrap()),
        2
    );
}

#[test]
fn a_store_write_failure_poisons_the_layer() {
    let (mut origin, mut cow, _events) = setup();
    cow.fail_at = Some(2);
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    assert!(layer.write_all(&vec![1; SIZE]).is_err());
    assert!(layer.write_all(&vec![2; SIZE]).is_err());
}

#[test]
fn a_cow_retirement_failure_poisons_the_layer() {
    let (mut origin, mut cow, _events) = setup();
    cow.fail_sync_at = Some(3);
    let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
    layer.write_all(&vec![1; SIZE]).unwrap();

    assert!(layer.merge().is_err());
    assert!(layer.read(&mut [0]).is_err());
}

#[test]
fn malformed_or_truncated_stores_are_rejected() {
    let mut origin = Cursor::new(vec![0; SIZE]);
    let mut cow = Cursor::new(vec![0; 2 * SIZE]);
    let error = Layer::open(&mut origin, &mut cow).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn create_validates_cow_size_immediately() {
    let origin = Cursor::new(vec![0; SIZE]);
    let cow = Cursor::new(vec![0; SIZE + 1]);
    let error = Layer::create(origin, cow, CHUNK_SIZE).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn open_rejects_a_header_incompatible_with_endpoint_geometry() {
    let mut origin = Cursor::new(vec![0; 65_536]);
    let mut cow = Cursor::new(vec![0; 3 * 65_536]);
    {
        let mut layer = Layer::create(&mut origin, &mut cow, CHUNK_SIZE).unwrap();
        layer.flush().unwrap();
    }

    let origin = (&mut origin)
        .scale(NonZeroU32::new(65_536).unwrap())
        .unwrap();
    let cow = (&mut cow).scale(NonZeroU32::new(65_536).unwrap()).unwrap();
    let error = Layer::open(origin, cow).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
