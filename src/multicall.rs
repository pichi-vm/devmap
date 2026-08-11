// SPDX-License-Identifier: Apache-2.0

//! Multi-call dispatch: when the binary is invoked under a legacy tool's
//! name (via a symlink), rewrite the arguments so the canonical
//! noun-first parser handles them. `ln -s devmap dmsetup` then makes
//! `dmsetup create …` run `devmap dm create …`.

use std::ffi::OsString;

/// Every legacy tool name this binary answers to when symlinked. Kept in
/// one place so `install-links` creates exactly the set `normalize`
/// dispatches (the prepend-style personas in [`persona_for`] plus the
/// option-style `dmzadm` handled by [`translate_dmzadm`]).
pub(crate) const LEGACY_NAMES: &[&str] = &["dmsetup", "veritysetup", "integritysetup", "dmzadm"];

/// Map a legacy program name to the `devmap` object it fronts. Only tools
/// whose persona exists are listed; the rest fall through to `devmap`.
fn persona_for(program: &str) -> Option<&'static str> {
    match program {
        "dmsetup" => Some("dm"),
        "veritysetup" => Some("verity"),
        "integritysetup" => Some("integrity"),
        _ => None,
    }
}

/// Rewrite `argv` for the canonical parser. If `argv[0]`'s basename names
/// a legacy tool, its object word is inserted so `dmsetup create …`
/// becomes `dmsetup dm create …`, which the parser reads as the `dm`
/// object. Verb-style tools map by this prepend; option-style ones (e.g.
/// `dmzadm`) get dedicated translators.
pub(crate) fn normalize(mut argv: Vec<OsString>) -> Vec<OsString> {
    let program = argv
        .first()
        .and_then(|a| a.to_str())
        .map(basename)
        .unwrap_or_default();
    if program == "dmzadm" {
        return translate_dmzadm(argv);
    }
    if let Some(object) = persona_for(program) {
        argv.insert(1, OsString::from(object));
    }
    argv
}

/// Translate `dmzadm`'s option-style mode flags into the `zoned` object's
/// verbs. `dmzadm --format --seq=16 /dev/sdb` becomes
/// `dmzadm zoned format --seq=16 /dev/sdb`: the leading mode flag is
/// dropped and `zoned <verb>` inserted; all other arguments (including
/// `--label=`/`--seq=` value flags the `zoned` parser already accepts)
/// pass through unchanged. An unrecognised invocation is returned as-is so
/// the parser reports a normal error.
fn translate_dmzadm(argv: Vec<OsString>) -> Vec<OsString> {
    let verb_for = |flag: &str| match flag {
        "--format" => Some("format"),
        "--check" => Some("check"),
        "--start" => Some("start"),
        "--stop" => Some("stop"),
        "--status" => Some("status"),
        _ => None,
    };

    let mut out = Vec::with_capacity(argv.len() + 2);
    let mut iter = argv.into_iter();
    if let Some(program) = iter.next() {
        out.push(program);
    }
    let mut rest: Vec<OsString> = iter.collect();
    if let Some(pos) = rest
        .iter()
        .position(|a| a.to_str().and_then(verb_for).is_some())
    {
        let verb = verb_for(rest[pos].to_str().expect("checked above")).expect("checked above");
        rest.remove(pos);
        out.push(OsString::from("zoned"));
        out.push(OsString::from(verb));
    }
    out.extend(rest);
    out
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
    fn integritysetup_symlink_gets_the_integrity_object_prepended() {
        assert_eq!(
            norm(&["/usr/sbin/integritysetup", "format", "/dev/sdb"]),
            [
                "/usr/sbin/integritysetup",
                "integrity",
                "format",
                "/dev/sdb"
            ]
        );
    }

    #[test]
    fn dmzadm_format_translates_to_zoned_format() {
        assert_eq!(
            norm(&["/usr/sbin/dmzadm", "--format", "--seq=16", "/dev/sdb"]),
            [
                "/usr/sbin/dmzadm",
                "zoned",
                "format",
                "--seq=16",
                "/dev/sdb"
            ]
        );
    }

    #[test]
    fn dmzadm_start_translates_and_keeps_the_device() {
        assert_eq!(
            norm(&["dmzadm", "--start", "/dev/sdb"]),
            ["dmzadm", "zoned", "start", "/dev/sdb"]
        );
    }

    #[test]
    fn dmzadm_without_a_mode_flag_is_left_for_the_parser() {
        // No recognised mode flag: pass through so clap reports the error.
        assert_eq!(norm(&["dmzadm", "/dev/sdb"]), ["dmzadm", "/dev/sdb"]);
    }

    #[test]
    fn plain_devmap_is_untouched() {
        assert_eq!(norm(&["devmap", "dm", "ls"]), ["devmap", "dm", "ls"]);
    }

    #[test]
    fn unknown_program_names_fall_through() {
        assert_eq!(norm(&["whatever", "dm", "ls"]), ["whatever", "dm", "ls"]);
    }

    #[test]
    fn every_legacy_name_is_actually_dispatched() {
        // install-links promises these names work; given each tool's own
        // invocation, normalize must insert an object word rather than
        // leave the argv untouched (dmzadm is option-style, so it needs a
        // mode flag; the others are verb-style).
        for name in LEGACY_NAMES {
            let probe = if *name == "dmzadm" { "--format" } else { "status" };
            let out = norm(&[name, probe, "/dev/x"]);
            assert_eq!(
                out.len(),
                4,
                "{name} was not dispatched (argv unchanged): {out:?}"
            );
        }
    }
}
