// SPDX-License-Identifier: Apache-2.0

use devmap_core::traits::tokio::Geometry as _;
use devmap_zero::Zero;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

#[tokio::test]
async fn zero_has_the_same_asynchronous_interface() {
    let mut zero = Zero::new(17);
    assert_eq!(zero.block_size().unwrap().get(), 1);
    assert_eq!(zero.count().await.unwrap(), 17);

    zero.seek(std::io::SeekFrom::Start(11)).await.unwrap();
    let mut bytes = [0xff; 8];
    assert_eq!(zero.read(&mut bytes).await.unwrap(), 6);
    assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0xff, 0xff]);
}
