// SPDX-License-Identifier: Apache-2.0

//! Path 2: format a verity hash volume compatible with `veritysetup`.

use std::{
    fmt::Write as _,
    fs::{self, File},
    io::Write as _,
    process::Command,
};

use devmap_core::{BlockSize, Detect as _, Geometry};
use devmap_verity::{
    Format as _,
    header::{Algorithm, Constraint, HashType, Header, Salt},
};

#[test]
fn matches_veritysetup_byte_for_byte() {
    let directory = tempfile::tempdir().unwrap();
    let data_path = directory.path().join("data.img");
    let our_hash_path = directory.path().join("ours.img");
    let reference_hash_path = directory.path().join("veritysetup.img");

    // Both formatters consume the same deterministic protected data.
    let mut data = File::create(&data_path).unwrap();
    data.write_all(&vec![0x5a; 8 * 4096]).unwrap();
    drop(data);

    // Detect the storage geometry and select the remaining on-disk policy.
    let mut data = File::open(&data_path).unwrap();
    let mut hash = File::create(&our_hash_path).unwrap();
    let data_geometry = Geometry::<Constraint>::detect(&data).unwrap();
    let hash_block_size = BlockSize::<Constraint>::detect(&hash).unwrap();

    let header = Header {
        uuid: [0x5a; 16],
        hash_type: HashType::Normal,
        algorithm: Algorithm::Sha256,
        salt: Salt::new(&[1, 2, 3]).unwrap(),
        data: data_geometry,
        hash: hash_block_size,
    };

    // Our formatter writes the header and tree and returns the trusted root.
    let root = header.format(&mut data, &mut hash).unwrap();
    hash.flush().unwrap();
    drop(hash);

    // Ask the external reference implementation to format the same volume
    // with exactly the policy recorded in our header.
    let output = Command::new("veritysetup")
        .args([
            "format",
            "--format=1",
            "--data-block-size=4096",
            "--hash-block-size=4096",
            "--hash=sha256",
            "--salt=010203",
            "--uuid=5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a5a",
        ])
        .arg(&data_path)
        .arg(&reference_hash_path)
        .output()
        .expect("veritysetup must be installed for the format compatibility test");
    assert!(
        output.status.success(),
        "veritysetup format failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Compatibility covers the complete image: header, padding, and tree.
    let ours = fs::read(our_hash_path).unwrap();
    let reference = fs::read(reference_hash_path).unwrap();
    assert_eq!(ours, reference);

    // The independently stored root must agree as well.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let reference_root = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Root hash:"))
        .map(str::trim)
        .expect("veritysetup output must report a root hash");

    let mut encoded_root = String::with_capacity(root.len() * 2);
    for byte in root {
        write!(encoded_root, "{byte:02x}").unwrap();
    }

    assert_eq!(encoded_root, reference_root);
}
