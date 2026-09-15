// SPDX-License-Identifier: Apache-2.0

use std::io::{Cursor, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU32;

use devmap_snapshot::{
    Layer,
    traits::std::{Create, Geometry},
};

#[test]
fn file_geometry_includes_block_device_seek_extent_and_restores_position() {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&[0; 37]).unwrap();
    file.seek(SeekFrom::Start(11)).unwrap();

    assert_eq!(Geometry::count(&mut file).unwrap(), 37);
    assert_eq!(file.stream_position().unwrap(), 11);
}

#[test]
fn cursor_and_layer_report_their_geometry() {
    let mut cursor = Cursor::new(vec![0; 73]);
    cursor.set_position(19);
    assert_eq!(Geometry::count(&mut cursor).unwrap(), 73);
    assert_eq!(cursor.position(), 19);

    let origin = Cursor::new(vec![0; 73]);
    let cow = Cursor::new(vec![0; 8192]);
    let mut layer = Layer::create(origin, cow, NonZeroU32::new(8).unwrap()).unwrap();
    assert_eq!(Geometry::count(&mut layer).unwrap(), 73);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn tokio_file_geometry_restores_position() {
    use devmap_core::traits::tokio::Geometry;
    use tokio::io::{AsyncSeekExt as _, SeekFrom};

    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(41).unwrap();
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file.path())
        .await
        .unwrap();
    file.seek(SeekFrom::Start(13)).await.unwrap();

    assert_eq!(Geometry::count(&mut file).await.unwrap(), 41);
    assert_eq!(file.stream_position().await.unwrap(), 13);
}
