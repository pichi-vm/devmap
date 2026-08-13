// SPDX-License-Identifier: Apache-2.0

//! Rendering cache metadata as `cache_dump`'s XML.
//!
//! As with thin, this is an interchange format rather than a report:
//! `cache_restore` reads it back, so it has to match the reference tool
//! exactly.

use std::fmt::Write as _;

use base64::Engine as _;

use crate::cache::{self, Superblock};
use crate::{Blocks, Error};

/// Render the whole cache as `cache_dump`-compatible XML.
///
/// # Errors
///
/// Any structural error encountered while reading the metadata.
///
/// # Panics
///
/// Never: a cache block index is bounded by `cache_blocks`, a `u32`.
pub fn dump<B: Blocks + ?Sized>(blocks: &B) -> Result<String, Error> {
    let superblock = Superblock::read(blocks)?;
    let mappings = cache::mappings(blocks, &superblock)?;
    let hints = cache::hints(blocks, &superblock)?;

    let mut out = String::new();
    // Writing into a String cannot fail; the results are dropped rather
    // than propagated as errors that cannot occur.
    let _ = writeln!(
        out,
        r#"<superblock uuid="{}" block_size="{}" nr_cache_blocks="{}" policy="{}" hint_width="{}">"#,
        uuid(&superblock.uuid),
        superblock.data_block_size,
        superblock.cache_blocks,
        superblock.policy_name,
        superblock.policy_hint_size,
    );

    let _ = writeln!(out, "  <mappings>");
    for mapping in &mappings {
        let _ = writeln!(
            out,
            r#"    <mapping cache_block="{}" origin_block="{}" dirty="{}"/>"#,
            mapping.cache_block, mapping.origin_block, mapping.dirty
        );
    }
    let _ = writeln!(out, "  </mappings>");

    // Hints are emitted only for cache blocks that actually hold a mapping.
    if !hints.is_empty() {
        let _ = writeln!(out, "  <hints>");
        let encoder = base64::engine::general_purpose::STANDARD;
        for mapping in &mappings {
            let index = usize::try_from(mapping.cache_block).expect("index fits usize");
            if let Some(hint) = hints.get(index) {
                let _ = writeln!(
                    out,
                    r#"    <hint cache_block="{}" data="{}"/>"#,
                    mapping.cache_block,
                    encoder.encode(hint)
                );
            }
        }
        let _ = writeln!(out, "  </hints>");
    }

    // No trailing newline: cache_dump ends at the closing tag.
    let _ = write!(out, "</superblock>");
    Ok(out)
}

/// Render a uuid the way `cache_dump` does: empty when unset.
fn uuid(raw: &[u8; 16]) -> String {
    if raw.iter().all(|&b| b == 0) {
        return String::new();
    }
    raw.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_uuid_renders_empty() {
        assert_eq!(uuid(&[0u8; 16]), "");
    }

    #[test]
    fn hints_encode_as_standard_base64() {
        // cache_dump prints a four-byte zero hint as "AAAAAA==".
        let encoder = base64::engine::general_purpose::STANDARD;
        assert_eq!(encoder.encode([0u8; 4]), "AAAAAA==");
    }
}
