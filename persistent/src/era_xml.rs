// SPDX-License-Identifier: Apache-2.0

//! Rendering era metadata as `era_dump`'s XML.

use std::fmt::Write as _;

use crate::era::{self, Superblock};
use crate::{Blocks, Error};

/// Render the whole era device as `era_dump`-compatible XML.
///
/// # Errors
///
/// Any structural error encountered while reading the metadata.
pub fn dump<B: Blocks + ?Sized>(blocks: &B) -> Result<String, Error> {
    let superblock = Superblock::read(blocks)?;
    let writesets = era::writesets(blocks, &superblock)?;
    let eras = era::era_array(blocks, &superblock)?;

    let mut out = String::new();
    let _ = writeln!(
        out,
        r#"<superblock uuid="{}" block_size="{}" nr_blocks="{}" current_era="{}">"#,
        uuid(&superblock.uuid),
        superblock.data_block_size,
        superblock.nr_blocks,
        superblock.current_era,
    );

    for writeset in &writesets {
        let _ = writeln!(
            out,
            r#"  <writeset era="{}" nr_bits="{}">"#,
            writeset.era,
            writeset.bits.len()
        );
        // Every bit is listed, set or not, as era_dump does.
        for (block, set) in writeset.bits.iter().enumerate() {
            let _ = writeln!(out, r#"    <bit block="{block}" value="{set}"/>"#);
        }
        let _ = writeln!(out, "  </writeset>");
    }

    let _ = writeln!(out, "  <era_array>");
    for (block, era) in eras.iter().enumerate() {
        let _ = writeln!(out, r#"    <era block="{block}" era="{era}"/>"#);
    }
    let _ = writeln!(out, "  </era_array>");

    // No trailing newline: era_dump ends at the closing tag.
    let _ = write!(out, "</superblock>");
    Ok(out)
}

/// Render a uuid the way `era_dump` does: empty when unset.
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
}
