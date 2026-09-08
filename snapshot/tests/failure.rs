// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::type_complexity)]

use std::cell::RefCell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

use devmap_snapshot::{ChunkSize, Layer, SyncData};

const SIZE: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Write { at: u64, len: usize },
    Flush,
    SyncData,
}

struct Logged {
    inner: Cursor<Vec<u8>>,
    events: Rc<RefCell<Vec<Event>>>,
    fail_write: bool,
}

impl Read for Logged {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}

impl Write for Logged {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::other("injected write failure"));
        }
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
        Ok(())
    }
}

fn setup() -> (Cursor<Vec<u8>>, Logged, Rc<RefCell<Vec<Event>>>, u64) {
    let size = ChunkSize::from_sectors(8).unwrap();
    let origin_chunks = 4;
    let cow_bytes = size.cow_chunks(origin_chunks).unwrap() * SIZE as u64;
    let events = Rc::new(RefCell::new(Vec::new()));
    (
        Cursor::new(vec![0; origin_chunks as usize * SIZE]),
        Logged {
            inner: Cursor::new(vec![0; cow_bytes as usize]),
            events: events.clone(),
            fail_write: false,
        },
        events,
        cow_bytes,
    )
}

#[test]
fn flush_orders_data_before_pointer_without_claiming_pointer_durability() {
    let (mut origin, mut cow, events, cow_bytes) = setup();
    let mut layer = Layer::create(
        &mut origin,
        &mut cow,
        4 * SIZE as u64,
        cow_bytes,
        ChunkSize::from_sectors(8).unwrap(),
    )
    .unwrap();
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
    let (mut origin, mut cow, events, cow_bytes) = setup();
    let mut layer = Layer::create(
        &mut origin,
        &mut cow,
        4 * SIZE as u64,
        cow_bytes,
        ChunkSize::from_sectors(8).unwrap(),
    )
    .unwrap();
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
fn a_store_write_failure_poisons_the_layer() {
    let (mut origin, mut cow, _events, cow_bytes) = setup();
    cow.fail_write = true;
    let mut layer = Layer::create(
        &mut origin,
        &mut cow,
        4 * SIZE as u64,
        cow_bytes,
        ChunkSize::from_sectors(8).unwrap(),
    )
    .unwrap();
    assert!(layer.write_all(&vec![1; SIZE]).is_err());
    assert!(layer.write_all(&vec![2; SIZE]).is_err());
}

#[test]
fn malformed_or_truncated_stores_are_rejected() {
    let mut origin = Cursor::new(vec![0; SIZE]);
    let mut cow = Cursor::new(vec![0; 2 * SIZE]);
    let mut layer = Layer::open(&mut origin, &mut cow, SIZE as u64, (2 * SIZE) as u64).unwrap();
    assert_eq!(
        layer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
