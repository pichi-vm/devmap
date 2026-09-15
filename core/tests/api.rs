// SPDX-License-Identifier: Apache-2.0

use std::io::{Cursor, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU32;

use devmap_core::traits::std::*;

#[test]
fn cursor_reports_byte_geometry_without_moving() {
    let mut cursor = Cursor::new(vec![0; 73]);
    cursor.set_position(19);

    assert_eq!(cursor.block_size().unwrap().get(), 1);
    assert_eq!(cursor.count().unwrap(), 73);
    assert_eq!(cursor.position(), 19);
    cursor.sync_data().unwrap();
}

#[test]
fn scale_preserves_extent_and_forwards_io() {
    let mut device = Cursor::new(vec![0; 16])
        .scale(NonZeroU32::new(4).unwrap())
        .unwrap();

    assert_eq!(device.block_size().unwrap().get(), 4);
    assert_eq!(device.count().unwrap(), 4);
    device.write_all(&[1, 2, 3]).unwrap();
    device.rewind().unwrap();
    let mut bytes = [0; 3];
    device.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [1, 2, 3]);
    device.sync_data().unwrap();
}

#[test]
fn scale_rejects_incoherent_geometry() {
    let error = Cursor::new(vec![0; 16])
        .scale(NonZeroU32::new(3).unwrap())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let error = Cursor::new(vec![0; 15])
        .scale(NonZeroU32::new(4).unwrap())
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn slice_maps_a_block_range_to_a_zero_based_device() {
    let source = Cursor::new((0_u8..16).collect::<Vec<_>>())
        .scale(NonZeroU32::new(2).unwrap())
        .unwrap();
    let mut device = source.slice(2..5).unwrap();

    assert_eq!(device.block_size().unwrap().get(), 2);
    assert_eq!(device.count().unwrap(), 3);
    let mut bytes = Vec::new();
    device.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [4, 5, 6, 7, 8, 9]);
    assert_eq!(device.seek(SeekFrom::Start(0)).unwrap(), 0);
    assert_eq!(device.as_mut().stream_position().unwrap(), 4);
}

#[test]
fn slice_accepts_a_start_count_pair_and_every_standard_range_form() {
    let mut region = Cursor::new(vec![0; 8]).slice(..).unwrap();
    assert_eq!(region.count().unwrap(), 8);

    let mut region = Cursor::new(vec![0; 8]).slice(..3).unwrap();
    assert_eq!(region.count().unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(..=3).unwrap();
    assert_eq!(region.count().unwrap(), 4);

    let mut region = Cursor::new(vec![0; 8]).slice(3..).unwrap();
    assert_eq!(region.count().unwrap(), 5);

    let mut region = Cursor::new(vec![0; 8]).slice(2..=4).unwrap();
    assert_eq!(region.count().unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice((2, 3)).unwrap();
    assert_eq!(region.count().unwrap(), 3);
}

#[test]
fn slice_rejects_invalid_ranges_and_limits_writes() {
    let error = Cursor::new(vec![0; 8])
        .slice(std::hint::black_box(5)..4)
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let error = Cursor::new(vec![0; 8]).slice(7..9).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    let error = Cursor::new(vec![0; 8]).slice((u64::MAX, 1)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let mut device = Cursor::new(vec![0; 8]).slice(2..4).unwrap();
    assert_eq!(device.write(&[1, 2, 3]).unwrap(), 2);
    assert_eq!(device.write(&[4]).unwrap(), 0);
    assert_eq!(device.into_inner().into_inner(), [0, 0, 1, 2, 0, 0, 0, 0]);
}

#[test]
fn geometry_supports_dynamic_dispatch() {
    let mut device: Box<dyn Geometry> = Box::new(Cursor::new(vec![0; 7]));
    assert_eq!(device.block_size().unwrap().get(), 1);
    assert_eq!(device.count().unwrap(), 7);
}

#[test]
fn regular_files_report_coherent_geometry() {
    let mut file = tempfile::tempfile().unwrap();
    file.set_len(8).unwrap();
    assert_eq!(file.block_size().unwrap().get(), 1);
    assert_eq!(file.count().unwrap(), 8);
}
