// SPDX-License-Identifier: Apache-2.0

//! Root integration test for the `crypt` persona: have the real
//! `cryptsetup` create LUKS1 and LUKS2 volumes, unlock and activate them
//! with `devmap crypt open`, and round-trip data through the mapping.
//!
//! The security-relevant assertion is that the master key never reaches
//! the kernel table: `dmsetup table --showkeys` must show only the logon
//! key reference, and must not contain the master key's hex — which the
//! test obtains from `cryptsetup luksDump --dump-master-key` so it can
//! search for the real value rather than a guess.
//!
//! Skips cleanly without root or without cryptsetup.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use devmap_linux::Control;

const BIN: &str = env!("CARGO_BIN_EXE_devmap");
const PASSPHRASE: &str = "correct horse battery staple";

fn have_dm() -> bool {
    Control::open().is_ok()
}

fn have_cryptsetup() -> bool {
    Command::new("cryptsetup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A backing file attached as a loop device; detaches and deletes on drop.
struct LoopDevice {
    path: String,
    file_path: PathBuf,
}

impl LoopDevice {
    fn attach(file_path: PathBuf) -> Self {
        let out = Command::new("losetup")
            .args(["-f", "--show"])
            .arg(&file_path)
            .output()
            .expect("run losetup");
        assert!(
            out.status.success(),
            "losetup failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = String::from_utf8(out.stdout).unwrap().trim().to_string();
        Self { path, file_path }
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        let _ = Command::new("losetup").args(["-d", &self.path]).status();
        let _ = std::fs::remove_file(&self.file_path);
    }
}

/// Run a command, feeding the passphrase on stdin; returns (ok, stdout).
fn run_with_passphrase(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(PASSPHRASE.as_bytes())?;
            child.wait_with_output()
        })
        .expect("spawn");
    if !out.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Plain command runner returning (ok, stdout).
fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program).args(args).output().expect("spawn");
    if !out.status.success() {
        eprintln!("stderr: {}", String::from_utf8_lossy(&out.stderr));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The master key cryptsetup reports, as a lowercase hex string.
fn master_key_hex(volume: &Path) -> String {
    let (ok, stdout) = run_with_passphrase(
        "cryptsetup",
        &[
            "luksDump",
            "--dump-master-key",
            "--batch-mode",
            &volume.to_string_lossy(),
            "-",
        ],
    );
    assert!(ok, "luksDump --dump-master-key");
    let mut hex = String::new();
    let mut in_dump = false;
    for line in stdout.lines() {
        let row = if let Some((_, rest)) = line.split_once("MK dump:") {
            in_dump = true;
            rest
        } else if in_dump && (line.starts_with('\t') || line.starts_with("  ")) {
            line
        } else {
            if in_dump {
                break;
            }
            continue;
        };
        for token in row.split_whitespace() {
            if token.len() == 2 && u8::from_str_radix(token, 16).is_ok() {
                hex.push_str(&token.to_lowercase());
            }
        }
    }
    assert!(!hex.is_empty(), "no MK dump found in:\n{stdout}");
    hex
}

/// Exercise one LUKS version end to end.
fn open_close_roundtrip(kind: &str) {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }
    if !have_cryptsetup() {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let _ = Command::new("modprobe").arg("dm-crypt").status();

    let dir = std::env::temp_dir().join(format!("devmap-crypt-{kind}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let image = dir.join("volume.img");
    std::fs::File::create(&image)
        .and_then(|f| f.set_len(64 * 1024 * 1024))
        .expect("create backing file");

    // cryptsetup creates the volume; cheap KDF params keep this fast.
    let (ok, _) = run_with_passphrase(
        "cryptsetup",
        &[
            "luksFormat",
            "--type",
            kind,
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            &image.to_string_lossy(),
            "-",
        ],
    );
    if !ok {
        eprintln!("skipping: luksFormat --type {kind} failed");
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    let expected_key = master_key_hex(&image);

    let key_file = dir.join("passphrase");
    std::fs::write(&key_file, PASSPHRASE).expect("write key file");
    let loop_dev = LoopDevice::attach(image.clone());
    let name = format!("devmap-crypt-{kind}-{}", std::process::id());

    // devmap unlocks and activates the volume cryptsetup made.
    let (ok, _) = run(
        BIN,
        &[
            "crypt",
            "open",
            &loop_dev.path,
            &name,
            "--key-file",
            &key_file.to_string_lossy(),
        ],
    );
    assert!(ok, "devmap crypt open ({kind})");

    // THE security assertion: the kernel table must reference the key by
    // its logon description, and must not contain the key itself.
    let (ok, table) = run("dmsetup", &["table", "--showkeys", &name]);
    assert!(ok, "dmsetup table");
    assert!(
        table.contains("logon:devmap:"),
        "table should reference a logon key: {table}"
    );
    assert!(
        !table.to_lowercase().contains(&expected_key),
        "the master key must never appear in the dm table ({kind})"
    );

    // Data written through the mapping reads back, and the backing device
    // holds ciphertext rather than the plaintext.
    let node = format!("/dev/mapper/{name}");
    let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut opened = None;
    for _ in 0..50 {
        if let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
        {
            opened = Some(f);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let mapped = opened.expect("mapped crypt device opens");
    {
        use std::os::unix::fs::FileExt as _;
        mapped.write_all_at(&pattern, 0).expect("write");
        mapped.sync_all().expect("sync");
        let mut back = vec![0u8; pattern.len()];
        mapped.read_exact_at(&mut back, 0).expect("read");
        assert_eq!(back, pattern, "dm-crypt must serve the data written");
    }
    drop(mapped);

    let (ok, _) = run(BIN, &["crypt", "close", &name]);
    assert!(ok, "devmap crypt close");

    // With the mapping gone, the plaintext must not be findable on disk.
    let raw = std::fs::read(&loop_dev.file_path).expect("read backing image");
    assert!(
        !raw.windows(pattern.len()).any(|w| w == pattern.as_slice()),
        "plaintext must not be present on the backing device ({kind})"
    );

    drop(loop_dev);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opens_a_luks1_volume_cryptsetup_created() {
    open_close_roundtrip("luks1");
}

#[test]
fn opens_a_luks2_volume_cryptsetup_created() {
    open_close_roundtrip("luks2");
}

/// Create a volume with `devmap crypt format`, then require the real
/// `cryptsetup` to activate it and round-trip data — the write-path gate.
fn format_then_cryptsetup_opens(kind: &str) {
    if !have_dm() {
        eprintln!("skipping: no device-mapper access (run as root)");
        return;
    }
    if !have_cryptsetup() {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let _ = Command::new("modprobe").arg("dm-crypt").status();

    let dir = std::env::temp_dir().join(format!("devmap-fmt-{kind}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let image = dir.join("volume.img");
    std::fs::File::create(&image)
        .and_then(|f| f.set_len(64 * 1024 * 1024))
        .expect("create backing file");
    let key_file = dir.join("passphrase");
    std::fs::write(&key_file, PASSPHRASE).expect("write key file");
    let loop_dev = LoopDevice::attach(image.clone());

    // devmap creates the volume; pbkdf2 keeps the KDF cheap for the test.
    let (ok, _) = run(
        BIN,
        &[
            "crypt",
            "format",
            &loop_dev.path,
            "--type",
            kind,
            "--pbkdf",
            "pbkdf2",
            "--key-file",
            &key_file.to_string_lossy(),
        ],
    );
    assert!(ok, "devmap crypt format ({kind})");

    // The real cryptsetup must accept the header we wrote and activate it.
    let name = format!("devmap-fmt-{kind}-{}", std::process::id());
    let (ok, _) = run_with_passphrase(
        "cryptsetup",
        &["luksOpen", &loop_dev.path, &name, "--key-file", "-"],
    );
    assert!(
        ok,
        "cryptsetup must open the volume devmap created ({kind})"
    );

    let node = format!("/dev/mapper/{name}");
    let pattern: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    {
        use std::os::unix::fs::FileExt as _;
        let mapped = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&node)
            .expect("open the cryptsetup mapping");
        mapped.write_all_at(&pattern, 0).expect("write");
        mapped.sync_all().expect("sync");
        let mut back = vec![0u8; pattern.len()];
        mapped.read_exact_at(&mut back, 0).expect("read");
        assert_eq!(back, pattern, "round-trip through cryptsetup's mapping");
    }

    let (ok, _) = run("cryptsetup", &["close", &name]);
    assert!(ok, "cryptsetup close");
    drop(loop_dev);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cryptsetup_opens_a_luks1_volume_devmap_created() {
    format_then_cryptsetup_opens("luks1");
}

#[test]
fn cryptsetup_opens_a_luks2_volume_devmap_created() {
    format_then_cryptsetup_opens("luks2");
}

#[test]
fn dump_reports_header_fields_and_no_secrets() {
    if !have_cryptsetup() {
        eprintln!("skipping: cryptsetup not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("devmap-crypt-dump-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let image = dir.join("volume.img");
    std::fs::File::create(&image)
        .and_then(|f| f.set_len(32 * 1024 * 1024))
        .expect("create backing file");

    let (ok, _) = run_with_passphrase(
        "cryptsetup",
        &[
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            &image.to_string_lossy(),
            "-",
        ],
    );
    if !ok {
        std::fs::remove_dir_all(&dir).ok();
        return;
    }
    let expected_key = master_key_hex(&image);

    let (ok, out) = run(BIN, &["crypt", "dump", &image.to_string_lossy()]);
    assert!(ok, "devmap crypt dump");
    assert!(out.contains("Version:"), "{out}");
    assert!(out.contains("Cipher:"), "{out}");
    assert!(out.contains("Keyslot 0:"), "{out}");
    // dump exists to inspect a header, never to reveal one's secrets.
    assert!(
        !out.to_lowercase().contains(&expected_key),
        "dump must not print the master key"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cryptsetup_symlink_dispatches_to_the_crypt_persona() {
    let dir = std::env::temp_dir().join(format!("devmap-crypt-link-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let link = dir.join("cryptsetup");
    symlink(BIN, &link).expect("symlink");

    // `--help` needs no privileges and proves the argv rewrite happened.
    let (ok, out) = run(&link.to_string_lossy(), &["--help"]);
    assert!(ok, "cryptsetup --help via symlink");
    assert!(
        out.contains("open") && out.contains("dump"),
        "symlink should surface the crypt verbs: {out}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
