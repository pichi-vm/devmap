// SPDX-License-Identifier: Apache-2.0

mod common;

use common::{LoopDevice, Owned, ensure_module_loaded, open_control};
use devmap_core::parse::DevId;
use devmap_core::traits::std::SyncData as _;
use devmap_verity::{
    HashType, Hashes, Options, Scheme, VerityTarget,
    traits::std::{Format as _, OpenHashes as _, Scale as _, SliceBytes as _},
};
use std::{
    fs::OpenOptions,
    io::{Read as _, Write as _},
    num::NonZeroU32,
};

#[test]
fn kernel_accepts_both_hash_formats_nondefault_blocks_and_header_offsets() {
    let Some(control) = open_control() else {
        return;
    };
    ensure_module_loaded("dm-verity");
    for (case, (hash_type, data_size, hash_size)) in [
        (HashType::ChromeOs, 512, 4096),
        (HashType::Normal, 512, 512),
        (HashType::Normal, 4096, 4096),
    ]
    .into_iter()
    .enumerate()
    {
        let data = LoopDevice::create(&format!("verity-data-{case}"), 65536);
        let hashes = LoopDevice::create(&format!("verity-hash-{case}"), 1024 * 1024);
        let expected: Vec<_> = (0..65536).map(|n| u8::try_from(n % 251).unwrap()).collect();
        let mut data_writer = OpenOptions::new().write(true).open(&data.path).unwrap();
        data_writer.write_all(&expected).unwrap();
        data_writer.sync_all().unwrap();
        drop(data_writer);
        let data_blocks = std::fs::File::open(&data.path)
            .unwrap()
            .scale_to(NonZeroU32::new(data_size).unwrap())
            .unwrap();
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&hashes.path)
            .unwrap()
            .scale_to(NonZeroU32::new(hash_size).unwrap())
            .unwrap()
            .slice_bytes(16384..)
            .unwrap();
        let (_, root) = Scheme::default()
            .with_hash_type(hash_type)
            .with_salt(&[3; 17])
            .unwrap()
            .format(data_blocks, &mut output, [7; 16])
            .unwrap();
        output.sync_data().unwrap();
        drop(output);
        let hash_device = Hashes::open(
            std::fs::File::open(&hashes.path)
                .unwrap()
                .slice_bytes(16384..)
                .unwrap(),
        )
        .unwrap();
        let target = Options::default()
            .with_header_offset_bytes(16384, hash_device.shape().hash_block_size)
            .unwrap()
            .target(
                hash_device.scheme(),
                hash_device.shape(),
                DevId::from_path(&data.path).unwrap(),
                DevId::from_path(&hashes.path).unwrap(),
                &root,
            )
            .unwrap();
        let device = Owned::create(
            &control,
            &format!("devmap-test-verity-{}-{case}", std::process::id()),
        )
        .unwrap();
        device
            .builder()
            .read_only()
            .add(0, target.data_sectors(), target.clone())
            .unwrap()
            .load()
            .unwrap();
        device.resume().unwrap();
        let mut actual = Vec::new();
        device
            .open()
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap_or_else(|error| {
                panic!("case {case}, {hash_type}, {data_size}/{hash_size}: {error}")
            });
        assert_eq!(actual, expected);
        let row = device.table().unwrap().next().unwrap();
        assert_eq!(row.parse::<VerityTarget>().unwrap(), target);
    }
}
