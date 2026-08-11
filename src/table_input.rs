// SPDX-License-Identifier: Apache-2.0

//! Parsing a device-mapper table from a file or stdin, in the format
//! `dmsetup` accepts: one `<start> <length> <target> <params…>` row per
//! line, blank lines and `#` comments ignored.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// One parsed table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) start: u64,
    pub(crate) length: u64,
    pub(crate) target: String,
    pub(crate) params: String,
}

/// Read a table from `path`, or from stdin when `path` is `None` or `"-"`
/// (matching `dmsetup`, which reads stdin if no table is given).
pub(crate) fn read_table(path: Option<&Path>) -> Result<Vec<Row>> {
    let text = match path {
        Some(p) if p.as_os_str() != "-" => {
            std::fs::read_to_string(p).with_context(|| format!("read table {}", p.display()))?
        }
        _ => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("read table from stdin")?;
            s
        }
    };
    parse_table(&text)
}

/// Parse table text into rows. Pure; the I/O lives in [`read_table`].
pub(crate) fn parse_table(text: &str) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = i + 1;
        let mut words = line.split_whitespace();
        let mut next = |what: &str| -> Result<&str> {
            words
                .next()
                .with_context(|| format!("table line {lineno}: missing {what}"))
        };
        let start = next("start sector")?;
        let length = next("length")?;
        let target = next("target type")?;
        let start = start
            .parse()
            .with_context(|| format!("table line {lineno}: bad start sector {start:?}"))?;
        let length = length
            .parse()
            .with_context(|| format!("table line {lineno}: bad length {length:?}"))?;
        // The remaining tokens are the target params; re-join on single
        // spaces (the kernel splits on whitespace, so this is faithful).
        let params = words.collect::<Vec<_>>().join(" ");
        rows.push(Row {
            start,
            length,
            target: target.to_owned(),
            params,
        });
    }
    if rows.is_empty() {
        bail!("empty table");
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_multi_row_table_with_comments_and_blanks() {
        let text = "\
            # a comment\n\
            0 2048 linear 7:0 0\n\
            \n\
            2048 2048 zero\n";
        let rows = parse_table(text).unwrap();
        assert_eq!(
            rows,
            [
                Row {
                    start: 0,
                    length: 2048,
                    target: "linear".into(),
                    params: "7:0 0".into(),
                },
                Row {
                    start: 2048,
                    length: 2048,
                    target: "zero".into(),
                    params: String::new(),
                },
            ]
        );
    }

    #[test]
    fn collapses_runs_of_whitespace_in_params() {
        let rows = parse_table("0 8  linear   7:0    0\n").unwrap();
        assert_eq!(rows[0].params, "7:0 0");
    }

    #[test]
    fn rejects_short_and_malformed_rows() {
        assert!(parse_table("0 2048\n").is_err()); // missing target
        assert!(parse_table("x 2048 zero\n").is_err()); // bad start
        assert!(parse_table("# only comments\n").is_err()); // empty table
    }
}
