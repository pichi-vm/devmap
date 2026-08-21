// SPDX-License-Identifier: Apache-2.0

//! Real-kernel validation of the `crypt` target: build a dm-crypt mapping
//! over a loop device with a raw key, round-trip data through it, and read
//! the table back so the rendered row is proved against dm-crypt's own
//! parser and its status output.
//!
//! Requires root (for `/dev/mapper/control` and losetup); skips otherwise.

#![cfg(target_os = "linux")]

mod common;

use common::Owned;

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

use devmap_linux::targets::Crypt;
use devmap_linux::targets::crypt::Key;

#[test]
fn crypt_maps_a_device_and_round_trips_data() {
    let Some(control) = common::open_control() else {
        return;
    };
    common::ensure_module_loaded("dm-crypt");

    let backing = common::LoopDevice::create("crypt", 16 * 1024 * 1024);
    let backing_dev = control.by_node(&backing.path).expect("by_node backing");

    // A fixed key: this is a test vector, not a secret.
    let key = Key::Hex(vec![0x2b; 32]);
    let target = Crypt {
        allow_discards: true,
        ..Crypt::new("aes-xts-plain64", key, backing_dev.id())
    };
    let rendered = target.to_string();

    let sectors = 8192u64;
    let name = format!("devmap-test-crypt-{}", std::process::id());
    let dev = Owned::create(&control, &name).expect("DM_DEV_CREATE");
    dev.builder()
        .add(0, sectors, target.clone())
        .expect("add crypt target")
        .load()
        .expect("DM_TABLE_LOAD — the kernel must accept our rendered row");
    dev.resume().expect("resume dm-crypt");

    // The table read back must parse as `Crypt` and match what we rendered,
    // except that the kernel masks the key unless asked for it.
    let rows: Vec<_> = dev.table().expect("read table").collect();
    assert_eq!(rows.len(), 1);
    let reported = rows[0]
        .parse::<Crypt>()
        .expect("kernel row must parse as Crypt");
    assert_eq!(reported.cipher, "aes-xts-plain64");
    assert_eq!(reported.device, backing_dev.id());
    assert!(
        reported.allow_discards,
        "optional arg survived the round trip"
    );
    assert_eq!(
        reported.key.size(),
        32,
        "key size survives even though the bytes are masked"
    );
    // Everything except the key field renders identically.
    let strip_key = |row: &str| {
        let mut t: Vec<&str> = row.split_whitespace().collect();
        t[1] = "<key>";
        t.join(" ")
    };
    assert_eq!(strip_key(&reported.to_string()), strip_key(&rendered));

    // Serve real I/O through the mapping to prove it is live.
    let mut file = dev.open_rw().expect("open mapped dm-crypt device");
    let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    file.write_all(&pattern).expect("write through dm-crypt");
    file.flush().expect("flush");
    file.seek(SeekFrom::Start(0)).expect("seek");
    let mut readback = vec![0u8; pattern.len()];
    file.read_exact(&mut readback).expect("read back");
    assert_eq!(readback, pattern, "dm-crypt must serve the data written");
    drop(file);

    // The ciphertext on the backing device must NOT be the plaintext —
    // otherwise the mapping is not actually encrypting anything.
    let mut raw = std::fs::File::open(&backing.path).expect("open backing");
    let mut ciphertext = vec![0u8; pattern.len()];
    raw.read_exact(&mut ciphertext).expect("read backing");
    assert_ne!(
        ciphertext, pattern,
        "backing device must hold ciphertext, not plaintext"
    );
}
