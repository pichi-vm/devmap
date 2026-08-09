// SPDX-License-Identifier: Apache-2.0

//! The `writecache` target: caches writes on a fast device (SSD or
//! persistent memory) in front of a slower origin device.

use std::fmt;
use std::str::FromStr;

use crate::DevId;
use crate::table::{Params, ParseError, Target};

/// Backing store kind for a [`Writecache`] cache device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A regular block device (SSD).
    Ssd,
    /// Persistent memory (DAX).
    PersistentMemory,
}

/// A small fast device caching writes for a slower origin device. Only
/// `high_watermark`/`low_watermark` are exposed; the rest of the kernel
/// target's optional arguments are locked to their defaults. Build via
/// [`Writecache::builder`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Writecache {
    kind: Kind,
    origin: DevId,
    cache: DevId,
    block_size: u32,
    high_watermark_percent: Option<u32>,
    low_watermark_percent: Option<u32>,
}
impl Writecache {
    /// Start building a [`Writecache`]. The watermark options default to
    /// unset (kernel defaults).
    #[must_use]
    pub fn builder(kind: Kind, origin: DevId, cache: DevId, block_size: u32) -> Builder {
        Builder {
            kind,
            origin,
            cache,
            block_size,
            high_watermark_percent: None,
            low_watermark_percent: None,
        }
    }

    /// The backing store kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// The origin (slow) device.
    #[must_use]
    pub fn origin(&self) -> DevId {
        self.origin
    }
    /// The cache (fast) device.
    #[must_use]
    pub fn cache(&self) -> DevId {
        self.cache
    }
    /// The cache block size in bytes.
    #[must_use]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    /// The high watermark percentage, if set.
    #[must_use]
    pub fn high_watermark_percent(&self) -> Option<u32> {
        self.high_watermark_percent
    }
    /// The low watermark percentage, if set.
    #[must_use]
    pub fn low_watermark_percent(&self) -> Option<u32> {
        self.low_watermark_percent
    }
}
impl Target for Writecache {
    const NAME: &'static str = "writecache";
    type Table = Self;
    type Info = Info;
}
impl fmt::Display for Writecache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            Kind::Ssd => 's',
            Kind::PersistentMemory => 'p',
        };
        write!(
            f,
            "{kind} {} {} {}",
            self.origin, self.cache, self.block_size
        )?;
        let opt_count = 2
            * (u32::from(self.high_watermark_percent.is_some())
                + u32::from(self.low_watermark_percent.is_some()));
        write!(f, " {opt_count}")?;
        if let Some(hw) = self.high_watermark_percent {
            write!(f, " high_watermark {hw}")?;
        }
        if let Some(lw) = self.low_watermark_percent {
            write!(f, " low_watermark {lw}")?;
        }
        Ok(())
    }
}
impl FromStr for Writecache {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        let kind = match p.token()? {
            "s" => Kind::Ssd,
            "p" => Kind::PersistentMemory,
            _ => return Err(ParseError),
        };
        let origin = p.device()?;
        let cache = p.device()?;
        let block_size = p.value()?;

        // The count is of tokens, and every option this type models is a
        // `<key> <value>` pair, so an odd count can only mean an option it
        // doesn't model.
        let count: usize = p.value()?;
        let mut high_watermark_percent = None;
        let mut low_watermark_percent = None;
        let mut consumed = 0;
        while consumed < count {
            match p.token()? {
                "high_watermark" => high_watermark_percent = Some(p.value()?),
                "low_watermark" => low_watermark_percent = Some(p.value()?),
                _ => return Err(ParseError),
            }
            consumed += 2;
        }
        if consumed != count {
            return Err(ParseError);
        }
        p.end()?;

        Ok(Writecache {
            kind,
            origin,
            cache,
            block_size,
            high_watermark_percent,
            low_watermark_percent,
        })
    }
}

/// Builder for [`Writecache`] — see [`Writecache::builder`].
#[derive(Debug, Clone)]
pub struct Builder {
    kind: Kind,
    origin: DevId,
    cache: DevId,
    block_size: u32,
    high_watermark_percent: Option<u32>,
    low_watermark_percent: Option<u32>,
}
impl Builder {
    /// Start writeback once the cache is this percent full.
    #[must_use]
    pub fn high_watermark_percent(mut self, percent: u32) -> Self {
        self.high_watermark_percent = Some(percent);
        self
    }
    /// Stop writeback once the cache drops to this percent full.
    #[must_use]
    pub fn low_watermark_percent(mut self, percent: u32) -> Self {
        self.low_watermark_percent = Some(percent);
        self
    }
    /// Finish building the [`Writecache`].
    #[must_use]
    pub fn build(self) -> Writecache {
        Writecache {
            kind: self.kind,
            origin: self.origin,
            cache: self.cache,
            block_size: self.block_size,
            high_watermark_percent: self.high_watermark_percent,
            low_watermark_percent: self.low_watermark_percent,
        }
    }
}

/// [`Writecache`]'s runtime status: cache occupancy plus fourteen
/// counters covering hit rates and why writes took each path.
///
/// Every field is a plain counter; the kernel emits them positionally in
/// exactly the order below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Info {
    /// Whether the cache device has taken an I/O error. Once set, the
    /// target is degraded.
    pub has_error: bool,
    /// Cache blocks in total.
    pub blocks: u64,
    /// Cache blocks currently free.
    pub free_blocks: u64,
    /// Cache blocks currently being written back to the origin.
    pub writeback_blocks: u64,
    /// Reads served.
    pub reads: u64,
    /// Reads that hit the cache.
    pub read_hits: u64,
    /// Writes served.
    pub writes: u64,
    /// Writes that hit an uncommitted cache entry.
    pub write_hits_uncommitted: u64,
    /// Writes that hit a committed cache entry.
    pub write_hits_committed: u64,
    /// Writes sent straight to the origin, bypassing the cache.
    pub writes_around: u64,
    /// Writes that had to allocate a new cache block.
    pub writes_allocate: u64,
    /// Writes that stalled waiting for a block to be freed. Persistently
    /// non-zero means writeback is not keeping up.
    pub writes_blocked_on_freelist: u64,
    /// Flushes served.
    pub flushes: u64,
    /// Discards served.
    pub discards: u64,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            u32::from(self.has_error),
            self.blocks,
            self.free_blocks,
            self.writeback_blocks,
            self.reads,
            self.read_hits,
            self.writes,
            self.write_hits_uncommitted,
            self.write_hits_committed,
            self.writes_around,
            self.writes_allocate,
            self.writes_blocked_on_freelist,
            self.flushes,
            self.discards
        )
    }
}

impl FromStr for Info {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut p = Params::new(s);
        // The kernel prints the error field as a signed count rather than
        // a flag, so treat any non-zero value as "errored".
        let has_error = p.value::<i64>()? != 0;
        let info = Info {
            has_error,
            blocks: p.value()?,
            free_blocks: p.value()?,
            writeback_blocks: p.value()?,
            reads: p.value()?,
            read_hits: p.value()?,
            writes: p.value()?,
            write_hits_uncommitted: p.value()?,
            write_hits_committed: p.value()?,
            writes_around: p.value()?,
            writes_allocate: p.value()?,
            writes_blocked_on_freelist: p.value()?,
            flushes: p.value()?,
            discards: p.value()?,
        };
        p.end()?;
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::line;

    #[test]
    fn writecache_renders_mode_and_optional_watermarks() {
        let t = Writecache::builder(
            Kind::Ssd,
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            4096,
        )
        .high_watermark_percent(90)
        .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 writecache s 252:1 252:2 4096 2 high_watermark 90"
        );
    }

    #[test]
    fn writecache_renders_pmem_with_no_optional_args() {
        let t = Writecache::builder(
            Kind::PersistentMemory,
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            4096,
        )
        .build();
        assert_eq!(line(0, 8192, &t), "0 8192 writecache p 252:1 252:2 4096 0");
    }

    #[test]
    fn writecache_renders_low_watermark_only() {
        let t = Writecache::builder(
            Kind::Ssd,
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            4096,
        )
        .low_watermark_percent(20)
        .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 writecache s 252:1 252:2 4096 2 low_watermark 20"
        );
    }

    #[test]
    fn writecache_renders_both_watermarks() {
        let t = Writecache::builder(
            Kind::Ssd,
            DevId::new(252, 1).unwrap(),
            DevId::new(252, 2).unwrap(),
            4096,
        )
        .high_watermark_percent(90)
        .low_watermark_percent(20)
        .build();
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 writecache s 252:1 252:2 4096 4 high_watermark 90 low_watermark 20"
        );
    }

    #[test]
    fn writecache_display_from_str_round_trips_each_option_shape() {
        for kind in [Kind::Ssd, Kind::PersistentMemory] {
            let base = || {
                Writecache::builder(
                    kind,
                    DevId::new(252, 1).unwrap(),
                    DevId::new(252, 2).unwrap(),
                    4096,
                )
            };
            let cases = [
                base().build(),
                base().high_watermark_percent(90).build(),
                base().low_watermark_percent(20).build(),
                base()
                    .high_watermark_percent(90)
                    .low_watermark_percent(20)
                    .build(),
            ];
            for original in cases {
                assert_eq!(
                    original.to_string().parse::<Writecache>().as_ref(),
                    Ok(&original)
                );
            }
        }
    }

    #[test]
    fn writecache_from_str_rejects_a_count_disagreeing_with_the_options() {
        assert!(
            "s 252:1 252:2 4096 4 high_watermark 90"
                .parse::<Writecache>()
                .is_err()
        );
        assert!(
            "s 252:1 252:2 4096 1 high_watermark 90"
                .parse::<Writecache>()
                .is_err()
        );
    }

    #[test]
    fn writecache_from_str_rejects_unmodelled_options_and_modes() {
        // `writeback_jobs` is a real dm-writecache option this type
        // doesn't render.
        assert!(
            "s 252:1 252:2 4096 2 writeback_jobs 1024"
                .parse::<Writecache>()
                .is_err()
        );
        assert!("x 252:1 252:2 4096 0".parse::<Writecache>().is_err());
    }
}
