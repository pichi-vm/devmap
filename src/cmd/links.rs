// SPDX-License-Identifier: Apache-2.0

//! `devmap install-links <dir>` — create the legacy-tool symlinks that
//! make this binary answer to `dmsetup`, `veritysetup`, `integritysetup`,
//! and `dmzadm` via the multi-call shim (see [`crate::multicall`]).

use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

use crate::cli::InstallLinks;
use crate::multicall::LEGACY_NAMES;

pub(crate) fn run(a: &InstallLinks) -> Result<()> {
    let exe = std::env::current_exe().context("resolve the devmap binary path")?;
    install(&a.dir, a.force, &exe, LEGACY_NAMES)
}

/// Create a symlink to `exe` for each of `names` under `dir`.
///
/// Split from [`run`] so it can be tested with an arbitrary target and
/// directory — the only environment it touches is the filesystem.
fn install(dir: &Path, force: bool, exe: &Path, names: &[&str]) -> Result<()> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    for name in names {
        let link = dir.join(name);
        match std::fs::symlink_metadata(&link) {
            Ok(_) if force => {
                std::fs::remove_file(&link)
                    .with_context(|| format!("replace {}", link.display()))?;
            }
            Ok(_) => bail!("{} already exists (use --force to replace)", link.display()),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("stat {}", link.display())),
        }
        symlink(exe, &link).with_context(|| format!("link {}", link.display()))?;
        println!("{} -> {}", link.display(), exe.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_creates_and_replaces_links() {
        let dir = std::env::temp_dir().join(format!("devmap-links-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let exe = Path::new("/usr/local/bin/devmap");
        let names = ["dmsetup", "veritysetup"];

        install(&dir, false, exe, &names).expect("first install");
        for name in names {
            let link = dir.join(name);
            assert_eq!(
                std::fs::read_link(&link).expect("read link"),
                exe,
                "{name} points at the binary"
            );
        }

        // A second install without --force must refuse the existing link.
        assert!(
            install(&dir, false, exe, &names).is_err(),
            "existing links need --force"
        );
        // With --force it replaces them cleanly.
        install(&dir, true, exe, &names).expect("forced reinstall");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn install_rejects_a_missing_directory() {
        let dir = std::env::temp_dir().join(format!("devmap-nodir-{}", std::process::id()));
        assert!(install(&dir, false, Path::new("/x"), &["dmsetup"]).is_err());
    }
}
