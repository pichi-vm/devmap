// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "tokio")]

use std::io::Cursor;
use std::num::NonZeroU32;

use devmap_core::traits::tokio::*;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

#[test]
fn tokio_file_supplies_all_capabilities() {
    fn capable<T: Geometry + SyncData>() {}
    capable::<tokio::fs::File>();
}

#[tokio::test]
async fn cursor_geometry_has_the_asynchronous_interface() {
    let mut cursor = Cursor::new(vec![0; 16]);
    cursor.set_position(7);

    assert_eq!(cursor.block_size().unwrap().get(), 1);
    assert_eq!(cursor.count().await.unwrap(), 16);
    assert_eq!(cursor.position(), 7);
    cursor.sync_data().await.unwrap();
}

#[tokio::test]
async fn scale_and_slice_have_the_asynchronous_interface() {
    let device = Cursor::new((0_u8..16).collect::<Vec<_>>())
        .scale(NonZeroU32::new(2).unwrap())
        .await
        .unwrap();
    let mut device = device.slice(2..5).await.unwrap();

    assert_eq!(device.block_size().unwrap().get(), 2);
    assert_eq!(device.count().await.unwrap(), 3);
    let mut bytes = Vec::new();
    device.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, [4, 5, 6, 7, 8, 9]);

    device.rewind().await.unwrap();
    device.write_all(&[9, 8]).await.unwrap();
    device.sync_data().await.unwrap();
}

#[tokio::test]
async fn asynchronous_slice_accepts_every_range_form() {
    let mut region = Cursor::new(vec![0; 8]).slice((2, 3)).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(2..5).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(2..=4).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(3..).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 5);

    let mut region = Cursor::new(vec![0; 8]).slice(..3).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 3);

    let mut region = Cursor::new(vec![0; 8]).slice(..=3).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 4);

    let mut region = Cursor::new(vec![0; 8]).slice(..).await.unwrap();
    assert_eq!(region.count().await.unwrap(), 8);
}

#[tokio::test]
async fn asynchronous_geometry_supports_dynamic_dispatch() {
    let mut device: Box<dyn Geometry> = Box::new(Cursor::new(vec![0; 7]));
    assert_eq!(device.block_size().unwrap().get(), 1);
    assert_eq!(device.count().await.unwrap(), 7);

    let mut durable: Box<dyn SyncData> = Box::new(Cursor::new(Vec::<u8>::new()));
    durable.sync_data().await.unwrap();
}

#[tokio::test]
async fn byte_geometry_operations_match_synchronous_semantics() {
    use devmap_core::traits::tokio::{Scale as _, SliceBytes as _};
    use tokio::io::AsyncReadExt as _;
    let source = std::io::Cursor::new(vec![7; 8192])
        .scale_to(std::num::NonZeroU32::new(4096).unwrap())
        .await
        .unwrap();
    let mut region = source.slice_bytes(4096..).await.unwrap();
    let mut bytes = Vec::new();
    region.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, vec![7; 4096]);
    let source = std::io::Cursor::new(vec![0; 8192])
        .scale_to(std::num::NonZeroU32::new(512).unwrap())
        .await
        .unwrap();
    assert!(source.slice_bytes(1..512).await.is_err());
}
