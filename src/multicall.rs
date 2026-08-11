// SPDX-License-Identifier: Apache-2.0

//! Multi-call dispatch: when the binary is invoked under a legacy tool's
//! name (via a symlink), rewrite the arguments so the canonical
//! noun-first parser handles them. `ln -s devmap dmsetup` then makes
//! `dmsetup create …` run `devmap dm create …`.

use std::ffi::OsString;

/// Map a legacy program name to the `devmap` object it fronts. Only tools
/// whose persona exists are listed; the rest fall through to `devmap`.
fn persona_for(program: &str) -> Option<&'static str> {
    match program {
        "dmsetup" => Some("dm"),
        "veritysetup" => Some("verity"),
        _ => None,
    }
}

/// Rewrite `argv` for the canonical parser. If `argv[0]`'s basename names
/// a legacy tool, its object word is inserted so `dmsetup create …`
/// becomes `dmsetup dm create …`, which the parser reads as the `dm`
/// object. Verb-style tools map by this prepend; option-style ones (e.g.
/// `dmzadm`) get dedicated translators in their persona.
pub(crate) fn normalize(mut argv: Vec<OsString>) -> Vec<OsString> {
    let program = argv
        .first()
        .and_then(|a| a.to_str())
        .map(basename)
        .unwrap_or_default();
    if let Some(object) = persona_for(program) {
        argv.insert(1, OsString::from(object));
    }
    argv
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(args: &[&str]) -> Vec<String> {
        normalize(args.iter().map(OsString::from).collect())
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn dmsetup_symlink_gets_the_dm_object_prepended() {
        assert_eq!(
            norm(&["/usr/bin/dmsetup", "create", "foo"]),
            ["/usr/bin/dmsetup", "dm", "create", "foo"]
        );
    }

    #[test]
    fn veritysetup_symlink_gets_the_verity_object_prepended() {
        assert_eq!(
            norm(&["/usr/sbin/veritysetup", "open", "data", "v", "hash", "abc"]),
            [
                "/usr/sbin/veritysetup",
                "verity",
                "open",
                "data",
                "v",
                "hash",
                "abc"
            ]
        );
    }

    #[test]
    fn plain_devmap_is_untouched() {
        assert_eq!(norm(&["devmap", "dm", "ls"]), ["devmap", "dm", "ls"]);
    }

    #[test]
    fn unknown_program_names_fall_through() {
        assert_eq!(norm(&["whatever", "dm", "ls"]), ["whatever", "dm", "ls"]);
    }
}
