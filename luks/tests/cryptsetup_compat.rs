// SPDX-License-Identifier: Apache-2.0

//! Cross-validation against the real `cryptsetup`: format volumes with it,
//! unlock them with this crate, and assert the master key we recover is
//! byte-identical to the one `cryptsetup luksDump --dump-master-key`
//! reports.
//!
//! This is the correctness proof for the whole read path — a wrong KDF,
//! keyslot decryption, AF merge, or header offset all show up as a
//! mismatch here. It is the check pichi's LUKS-adjacent code never had.
//!
//! Skips cleanly when `cryptsetup` is absent. Formatting a file-backed
//! volume needs no root, so this runs in the normal test suite; cheap KDF
//! parameters keep it fast.

use std::path::Path;
use std::process::Command;

use devmap_luks::{Error, Header};

/// The passphrase every fixture in this file uses.
const PASSPHRASE: &[u8] = b"correct horse battery staple";

fn have_cryptsetup() -> bool {
    Command::new("cryptsetup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run `cryptsetup` with `args`, feeding [`PASSPHRASE`] on stdin.
fn run_cryptsetup(args: &[&str]) -> bool {
    let out = Command::new("cryptsetup")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(PASSPHRASE)?;
            child.wait_with_output()
        })
        .expect("run cryptsetup");
    if !out.status.success() {
        eprintln!(
            "cryptsetup {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.status.success()
}

/// `cryptsetup luksFormat` a file-backed volume with deliberately cheap KDF
/// parameters, so the test is fast and reproducible.
fn format_volume(path: &Path, kind: &str) -> bool {
    std::fs::File::create(path)
        .and_then(|f| f.set_len(32 * 1024 * 1024))
        .expect("create backing file");

    run_cryptsetup(&[
        "luksFormat",
        "--type",
        kind,
        "--batch-mode",
        "--pbkdf",
        "pbkdf2",
        "--pbkdf-force-iterations",
        "1000",
        &path.to_string_lossy(),
        "-",
    ])
}

/// The master key `cryptsetup` itself reports, as raw bytes.
fn cryptsetup_master_key(path: &Path) -> Vec<u8> {
    let out = Command::new("cryptsetup")
        .args(["luksDump", "--dump-master-key", "--batch-mode"])
        .arg(path)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(PASSPHRASE)?;
            child.wait_with_output()
        })
        .expect("run cryptsetup luksDump");
    assert!(out.status.success(), "luksDump --dump-master-key failed");

    // The dump prints "MK dump:" followed by indented hex byte rows.
    let text = String::from_utf8_lossy(&out.stdout);
    let mut bytes = Vec::new();
    let mut in_dump = false;
    for line in text.lines() {
        if let Some(rest) = line.split_once("MK dump:").map(|(_, r)| r) {
            in_dump = true;
            bytes.extend(hex_bytes(rest));
        } else if in_dump {
            // Continuation rows are indented; anything else ends the dump.
            if line.starts_with('\t') || line.starts_with("  ") {
                bytes.extend(hex_bytes(line));
            } else {
                break;
            }
        }
    }
    assert!(!bytes.is_empty(), "could not read MK dump from:\n{text}");
    bytes
}

/// Parse whitespace-separated hex byte pairs from one dump row.
fn hex_bytes(row: &str) -> Vec<u8> {
    row.split_whitespace()
        .filter(|t| t.len() == 2)
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .collect()
}

/// Format a volume of `kind`, unlock it with this crate, and require the
/// master key to match the one cryptsetup itself reports.
fn assert_unlocks(kind: &str, expected_payload_offset: u64) {
    if !have_cryptsetup() {
        eprintln!("skip: cryptsetup not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{kind}.img"));
    if !format_volume(&path, kind) {
        return;
    }

    let image = std::fs::read(&path).expect("read volume");
    let header = Header::parse(&image).unwrap_or_else(|e| panic!("parse {kind} header: {e}"));
    assert_eq!(header.cipher_spec().expect("cipher"), "aes-xts-plain64");
    assert_eq!(header.key_bytes(), 64);

    let expected = cryptsetup_master_key(&path);
    let recovered = header
        .unlock(PASSPHRASE, &image.as_slice())
        .unwrap_or_else(|e| panic!("unlock {kind} with the correct passphrase: {e}"));
    assert_eq!(
        recovered.expose(),
        expected.as_slice(),
        "our {kind} master key must equal the one cryptsetup reports"
    );

    // The header fields we hand to dm-crypt must agree with cryptsetup's.
    assert_eq!(
        header.payload_offset_bytes().expect("payload offset"),
        expected_payload_offset
    );
    assert_eq!(
        header.uuid().len(),
        36,
        "uuid is the canonical hyphenated form: {}",
        header.uuid()
    );
}

#[test]
fn unlocks_a_luks1_volume_cryptsetup_created() {
    // LUKS1 puts the payload at 4096 sectors.
    assert_unlocks("luks1", 4096 * 512);
}

#[test]
fn unlocks_a_luks2_volume_cryptsetup_created() {
    // LUKS2 defaults to a 16 MiB header + keyslots region.
    assert_unlocks("luks2", 16 * 1024 * 1024);
}

#[test]
fn unlocks_a_luks2_volume_with_an_argon2id_keyslot() {
    // The default KDF, and the one the other tests deliberately avoid for
    // speed — so exercise it once with cheap parameters.
    if !have_cryptsetup() {
        eprintln!("skip: cryptsetup not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("argon.img");
    std::fs::File::create(&path)
        .and_then(|f| f.set_len(32 * 1024 * 1024))
        .expect("create backing file");

    let ok = run_cryptsetup(&[
        "luksFormat",
        "--type",
        "luks2",
        "--batch-mode",
        "--pbkdf",
        "argon2id",
        "--pbkdf-force-iterations",
        "4",
        "--pbkdf-memory",
        "32",
        "--pbkdf-parallel",
        "1",
        &path.to_string_lossy(),
        "-",
    ]);
    if !ok {
        eprintln!("skip: argon2id luksFormat failed");
        return;
    }

    let image = std::fs::read(&path).expect("read volume");
    let header = Header::parse(&image).expect("parse header");
    let recovered = header
        .unlock(PASSPHRASE, &image.as_slice())
        .expect("unlock an argon2id keyslot");
    assert_eq!(recovered.expose(), cryptsetup_master_key(&path).as_slice());
}

#[test]
fn rejects_a_wrong_passphrase() {
    if !have_cryptsetup() {
        eprintln!("skip: cryptsetup not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("luks1.img");
    if !format_volume(&path, "luks1") {
        return;
    }

    let image = std::fs::read(&path).expect("read volume");
    let header = Header::parse(&image).expect("parse header");
    // A wrong passphrase must be a clean NoKey, not a garbage key: that is
    // what the master-key digest in the header is for.
    assert!(matches!(
        header.unlock(b"wrong passphrase", &image.as_slice()),
        Err(Error::NoKey)
    ));
}

/// A deterministic entropy stream, so a formatted volume is reproducible.
struct Counter(u8);
impl devmap_luks::format::Entropy for Counter {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        for byte in buf.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// Create a volume with **our** formatter and require the real
/// `cryptsetup` to understand it.
///
/// This is the safety gate for the write path: our own reader agreeing
/// with our own writer proves nothing about interoperability, but
/// `cryptsetup luksDump` parsing the header does.
fn assert_cryptsetup_reads_our_header(version: devmap_luks::Version, expect: &str) {
    if !have_cryptsetup() {
        eprintln!("skip: cryptsetup not installed");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ours.img");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create image");
    file.set_len(64 * 1024 * 1024).expect("size image");
    let mut file = file;

    let options = devmap_luks::FormatOptions {
        version,
        kdf: devmap_luks::kdf::Kdf::Pbkdf2 {
            hash: devmap_luks::Hash::Sha256,
            iterations: 1000,
        },
        digest_iterations: 1000,
        uuid: "1b4e28ba-2fa1-11d2-883f-0016d3cca427".to_owned(),
        ..devmap_luks::FormatOptions::default()
    };
    devmap_luks::format::format(&mut file, &options, PASSPHRASE, &mut Counter(1))
        .expect("format the volume");
    drop(file);

    let out = Command::new("cryptsetup")
        .args(["luksDump", &path.to_string_lossy()])
        .output()
        .expect("run luksDump");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cryptsetup must parse the header we wrote: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains(expect), "luksDump output:\n{text}");
    assert!(
        text.contains("1b4e28ba-2fa1-11d2-883f-0016d3cca427"),
        "our uuid must survive: {text}"
    );

    // And it must recover the same master key from our keyslot — proof the
    // keyslot wrapping, not merely the header layout, is correct.
    let ours = {
        let image = std::fs::read(&path).expect("read image");
        let header = devmap_luks::Header::parse(&image).expect("parse our own header");
        header
            .unlock(PASSPHRASE, &image.as_slice())
            .expect("unlock our own volume")
    };
    assert_eq!(
        ours.expose(),
        cryptsetup_master_key(&path).as_slice(),
        "cryptsetup must derive the same master key from our keyslot"
    );
}

#[test]
fn cryptsetup_reads_a_luks1_volume_we_created() {
    assert_cryptsetup_reads_our_header(devmap_luks::Version::V1, "Version:       \t1");
}

#[test]
fn cryptsetup_reads_a_luks2_volume_we_created() {
    assert_cryptsetup_reads_our_header(devmap_luks::Version::V2, "Version:       \t2");
}

#[test]
fn rejects_a_device_that_is_not_luks() {
    let not_luks = vec![0u8; 4096];
    assert!(matches!(
        Header::parse(&not_luks),
        Err(devmap_luks::Error::BadMagic)
    ));
}
