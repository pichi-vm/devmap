// SPDX-License-Identifier: Apache-2.0

//! Parsing `thin_dump`'s XML back into structures.
//!
//! The dialect is small and machine-generated — four element types, all
//! attributes, no text content or namespaces — so this is a focused parser
//! rather than a general XML one. It is deliberately strict: an unknown
//! element or a missing attribute is an error, because this input rebuilds
//! a pool and quietly ignoring part of it would silently lose mappings.

use crate::Error;

/// A parsed `<superblock>` and everything under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    /// Pool uuid; empty when unset.
    pub uuid: String,
    /// The pool's timestamp.
    pub time: u32,
    /// Transaction id.
    pub transaction: u64,
    /// Metadata format version.
    pub version: u32,
    /// Data block size in 512-byte sectors.
    pub data_block_size: u32,
    /// Data blocks the pool covers.
    pub nr_data_blocks: u64,
    /// The devices, in the order they appeared.
    pub devices: Vec<Device>,
}

/// A `<device>` and its mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Device id.
    pub dev_id: u64,
    /// Blocks the device maps.
    pub mapped_blocks: u64,
    /// Transaction the device was created in.
    pub transaction: u64,
    /// Pool time at creation.
    pub creation_time: u32,
    /// Pool time at last snapshot.
    pub snap_time: u32,
    /// Mappings, expanded from ranges, in ascending origin order.
    pub mappings: Vec<Mapping>,
}

/// One expanded mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// Block within the thin device.
    pub origin_block: u64,
    /// Block within the pool's data device.
    pub data_block: u64,
    /// Pool time the mapping was made.
    pub time: u32,
}

/// One element: its name and attributes.
struct Element<'a> {
    name: &'a str,
    attrs: Vec<(&'a str, &'a str)>,
}

impl Element<'_> {
    /// The value of `name`, or an error naming what was missing.
    fn get(&self, name: &str) -> Result<&str, Error> {
        self.attrs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| *v)
            .ok_or_else(|| Error::Malformed {
                block: 0,
                reason: format!("<{}> has no {name} attribute", self.name),
            })
    }

    /// The value of `name`, parsed.
    fn parse<T: std::str::FromStr>(&self, name: &str) -> Result<T, Error> {
        let raw = self.get(name)?;
        raw.parse().map_err(|_| Error::Malformed {
            block: 0,
            reason: format!("<{}> {name}={raw:?} is not a number", self.name),
        })
    }
}

/// Split `text` into elements, ignoring whitespace between them.
///
/// Returns each element with a flag for whether it was self-closing, and
/// treats `</name>` as an element named `/name`.
fn elements(text: &str) -> Result<Vec<(Element<'_>, bool)>, Error> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let end = rest.find('>').ok_or_else(|| Error::Malformed {
            block: 0,
            reason: "unterminated element".to_owned(),
        })?;
        let body = &rest[..end];
        rest = &rest[end + 1..];

        let self_closing = body.ends_with('/');
        let body = body.strip_suffix('/').unwrap_or(body).trim();
        let mut parts = body.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or_default();
        let attrs = parse_attrs(parts.next().unwrap_or_default())?;
        out.push((Element { name, attrs }, self_closing));
    }
    Ok(out)
}

/// Parse `key="value"` pairs.
fn parse_attrs(mut text: &str) -> Result<Vec<(&str, &str)>, Error> {
    let mut attrs = Vec::new();
    loop {
        text = text.trim_start();
        if text.is_empty() {
            return Ok(attrs);
        }
        let eq = text.find('=').ok_or_else(|| Error::Malformed {
            block: 0,
            reason: format!("attribute without a value near {text:?}"),
        })?;
        let key = text[..eq].trim();
        let after = text[eq + 1..].trim_start();
        let quoted = after.strip_prefix('"').ok_or_else(|| Error::Malformed {
            block: 0,
            reason: format!("attribute {key} is not quoted"),
        })?;
        let close = quoted.find('"').ok_or_else(|| Error::Malformed {
            block: 0,
            reason: format!("attribute {key} has no closing quote"),
        })?;
        attrs.push((key, &quoted[..close]));
        text = &quoted[close + 1..];
    }
}

/// Parse a `thin_dump` document.
///
/// # Errors
///
/// [`Error::Malformed`] for anything the dialect does not allow — an
/// unknown element, a missing attribute, a mapping outside a device.
///
/// # Panics
///
/// Never: each `take()` below is guarded by the `is_some` check above it.
pub fn parse(text: &str) -> Result<Pool, Error> {
    let malformed = |reason: String| Error::Malformed { block: 0, reason };

    let mut pool: Option<Pool> = None;
    let mut device: Option<Device> = None;

    for (element, self_closing) in elements(text)? {
        match element.name {
            "superblock" => {
                pool = Some(Pool {
                    uuid: element.get("uuid").unwrap_or("").to_owned(),
                    time: element.parse("time")?,
                    transaction: element.parse("transaction")?,
                    version: element.parse("version")?,
                    data_block_size: element.parse("data_block_size")?,
                    nr_data_blocks: element.parse("nr_data_blocks")?,
                    devices: Vec::new(),
                });
            }
            "/superblock" => {}
            "device" => {
                if device.is_some() {
                    return Err(malformed("<device> nested inside another".to_owned()));
                }
                device = Some(Device {
                    dev_id: element.parse("dev_id")?,
                    mapped_blocks: element.parse("mapped_blocks")?,
                    transaction: element.parse("transaction")?,
                    creation_time: element.parse("creation_time")?,
                    snap_time: element.parse("snap_time")?,
                    mappings: Vec::new(),
                });
                if self_closing {
                    let finished = device.take().expect("just set");
                    pool.as_mut()
                        .ok_or_else(|| malformed("<device> outside <superblock>".to_owned()))?
                        .devices
                        .push(finished);
                }
            }
            "/device" => {
                let finished = device
                    .take()
                    .ok_or_else(|| malformed("</device> without <device>".to_owned()))?;
                pool.as_mut()
                    .ok_or_else(|| malformed("<device> outside <superblock>".to_owned()))?
                    .devices
                    .push(finished);
            }
            "single_mapping" | "range_mapping" => {
                let target = device
                    .as_mut()
                    .ok_or_else(|| malformed(format!("<{}> outside a device", element.name)))?;
                if element.name == "single_mapping" {
                    target.mappings.push(Mapping {
                        origin_block: element.parse("origin_block")?,
                        data_block: element.parse("data_block")?,
                        time: element.parse("time")?,
                    });
                } else {
                    // A range is shorthand for consecutive mappings; expand
                    // it so downstream code sees one uniform representation.
                    let origin: u64 = element.parse("origin_begin")?;
                    let data: u64 = element.parse("data_begin")?;
                    let length: u64 = element.parse("length")?;
                    let time: u32 = element.parse("time")?;
                    for i in 0..length {
                        target.mappings.push(Mapping {
                            origin_block: origin + i,
                            data_block: data + i,
                            time,
                        });
                    }
                }
            }
            other if other.starts_with('?') || other.starts_with('!') => {}
            other => {
                return Err(malformed(format!("unknown element <{other}>")));
            }
        }
    }

    let mut pool = pool.ok_or_else(|| malformed("no <superblock>".to_owned()))?;
    if device.is_some() {
        return Err(malformed("unclosed <device>".to_owned()));
    }
    // Downstream builders assume ascending keys throughout.
    pool.devices.sort_by_key(|d| d.dev_id);
    for device in &mut pool.devices {
        device.mappings.sort_by_key(|m| m.origin_block);
    }
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<superblock uuid="" time="1" transaction="2" version="2" data_block_size="128" nr_data_blocks="4096">
  <device dev_id="1" mapped_blocks="3" transaction="0" creation_time="0" snap_time="1">
    <range_mapping origin_begin="0" data_begin="0" length="2" time="0"/>
    <single_mapping origin_block="5" data_block="7" time="1"/>
  </device>
</superblock>"#;

    #[test]
    fn parses_a_dump_and_expands_ranges() {
        let pool = parse(SAMPLE).expect("parse");
        assert_eq!(pool.time, 1);
        assert_eq!(pool.transaction, 2);
        assert_eq!(pool.nr_data_blocks, 4096);
        assert_eq!(pool.devices.len(), 1);

        let device = &pool.devices[0];
        assert_eq!(device.dev_id, 1);
        assert_eq!(device.snap_time, 1);
        // The 2-block range became two mappings, plus the single one.
        assert_eq!(
            device.mappings,
            [
                Mapping {
                    origin_block: 0,
                    data_block: 0,
                    time: 0
                },
                Mapping {
                    origin_block: 1,
                    data_block: 1,
                    time: 0
                },
                Mapping {
                    origin_block: 5,
                    data_block: 7,
                    time: 1
                },
            ]
        );
    }

    #[test]
    fn parses_a_pool_with_no_devices() {
        let pool = parse(
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128" nr_data_blocks="16">
</superblock>"#,
        )
        .expect("parse");
        assert_eq!(pool.devices.len(), 0);
    }

    #[test]
    fn accepts_a_self_closing_device() {
        let pool = parse(
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128" nr_data_blocks="16">
  <device dev_id="4" mapped_blocks="0" transaction="0" creation_time="0" snap_time="0"/>
</superblock>"#,
        )
        .expect("parse");
        assert_eq!(pool.devices.len(), 1);
        assert_eq!(pool.devices[0].mappings.len(), 0);
    }

    #[test]
    fn sorts_devices_and_mappings() {
        let pool = parse(
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128" nr_data_blocks="16">
  <device dev_id="9" mapped_blocks="1" transaction="0" creation_time="0" snap_time="0">
    <single_mapping origin_block="7" data_block="1" time="0"/>
    <single_mapping origin_block="2" data_block="0" time="0"/>
  </device>
  <device dev_id="3" mapped_blocks="0" transaction="0" creation_time="0" snap_time="0"/>
</superblock>"#,
        )
        .expect("parse");
        assert_eq!(pool.devices[0].dev_id, 3, "devices ascend");
        let origins: Vec<u64> = pool.devices[1]
            .mappings
            .iter()
            .map(|m| m.origin_block)
            .collect();
        assert_eq!(origins, [2, 7], "mappings ascend");
    }

    #[test]
    fn rejects_input_it_would_otherwise_silently_lose() {
        // Each of these would drop or misplace data if tolerated.
        for bad in [
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128" nr_data_blocks="16">
  <unexpected/>
</superblock>"#,
            // a mapping with no enclosing device
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128" nr_data_blocks="16">
  <single_mapping origin_block="0" data_block="0" time="0"/>
</superblock>"#,
            // missing a required attribute
            r#"<superblock uuid="" time="0" transaction="0" version="2" data_block_size="128">
</superblock>"#,
            // no superblock at all
            r#"<device dev_id="1" mapped_blocks="0" transaction="0" creation_time="0" snap_time="0"/>"#,
        ] {
            assert!(parse(bad).is_err(), "should reject: {bad}");
        }
    }
}
