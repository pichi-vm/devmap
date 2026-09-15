// SPDX-License-Identifier: Apache-2.0

use std::io::Cursor;

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
