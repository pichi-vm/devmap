// SPDX-License-Identifier: Apache-2.0

//! The focused CLI and its supported compatibility entry points, without root.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_devmap");

#[test]
fn supported_commands_have_help_and_retired_commands_are_rejected() {
    for command in ["dm", "crypt", "verity", "snapshot", "install-links"] {
        let output = Command::new(BIN)
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{command}: {output:?}");
    }
    for command in ["integrity", "zoned", "thin", "cache", "era"] {
        let output = Command::new(BIN)
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{command} is still exposed");
    }
}

#[test]
fn install_links_creates_only_the_supported_compatibility_entry_points() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new(BIN)
        .arg("install-links")
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let mut names: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["cryptsetup", "dmsetup", "veritysetup"]);
    for (name, object) in [
        ("cryptsetup", "crypt"),
        ("dmsetup", "dm"),
        ("veritysetup", "verity"),
    ] {
        let link = directory.path().join(name);
        assert!(link.is_symlink());
        let output = Command::new(link).arg("--help").output().unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains(&format!("{name} {object}"))
        );
    }
}
