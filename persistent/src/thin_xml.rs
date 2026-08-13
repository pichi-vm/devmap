// SPDX-License-Identifier: Apache-2.0

//! Rendering thin metadata as `thin_dump`'s XML.
//!
//! The XML is not merely a report: `thin_restore` consumes it to rebuild a
//! pool, so it is the interchange format for backing metadata up and
//! restoring it. That makes matching thin-provisioning-tools byte-for-byte
//! the requirement, not a nicety — anything else is a dialect that its
//! tools cannot read back.

use std::fmt::Write as _;

use crate::thin::{self, Superblock};
use crate::{Blocks, Error};

/// Render the whole pool as `thin_dump`-compatible XML.
///
/// # Errors
///
/// Any structural error encountered while reading the metadata.
pub fn dump<B: Blocks + ?Sized>(blocks: &B) -> Result<String, Error> {
    let superblock = Superblock::read(blocks)?;
    let devices = thin::devices(blocks, &superblock)?;

    let mut out = String::new();
    // `writeln!` into a String cannot fail, so the results are discarded
    // deliberately rather than propagated as impossible errors.
    let _ = writeln!(
        out,
        r#"<superblock uuid="{}" time="{}" transaction="{}" version="{}" data_block_size="{}" nr_data_blocks="{}">"#,
        uuid(&superblock.uuid),
        superblock.time,
        superblock.transaction_id,
        superblock.version,
        superblock.data_block_size,
        superblock.nr_data_blocks(),
    );

    for (dev_id, details) in devices {
        let _ = writeln!(
            out,
            r#"  <device dev_id="{dev_id}" mapped_blocks="{}" transaction="{}" creation_time="{}" snap_time="{}">"#,
            details.mapped_blocks,
            details.transaction_id,
            details.creation_time,
            details.snapshotted_time,
        );
        // Consecutive mappings that advance together are emitted as one
        // range, exactly as thin_dump does.
        for run in thin::coalesce(&thin::mappings(blocks, &superblock, dev_id)?) {
            if run.length == 1 {
                let _ = writeln!(
                    out,
                    r#"    <single_mapping origin_block="{}" data_block="{}" time="{}"/>"#,
                    run.origin_begin, run.data_begin, run.time
                );
            } else {
                let _ = writeln!(
                    out,
                    r#"    <range_mapping origin_begin="{}" data_begin="{}" length="{}" time="{}"/>"#,
                    run.origin_begin, run.data_begin, run.length, run.time
                );
            }
        }
        let _ = writeln!(out, "  </device>");
    }

    // No trailing newline: thin_dump ends the document at the closing tag,
    // and this output is compared against it byte for byte.
    let _ = write!(out, "</superblock>");
    Ok(out)
}

/// Render a pool uuid the way `thin_dump` does: empty when unset, rather
/// than a string of zeros.
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
    fn a_set_uuid_renders_as_hex() {
        let mut raw = [0u8; 16];
        raw[0] = 0xAB;
        raw[15] = 0x01;
        assert_eq!(uuid(&raw), "ab000000000000000000000000000001");
    }
}
