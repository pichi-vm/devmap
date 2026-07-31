// SPDX-License-Identifier: Apache-2.0

//! The `writecache` target: caches writes on a fast device (SSD or
//! persistent memory) in front of a slower origin device.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// The kernel's default high watermark (percent) when unset.
const DEFAULT_HIGH_WATERMARK: u32 = 50;
/// The kernel's default low watermark (percent) when unset.
const DEFAULT_LOW_WATERMARK: u32 = 45;

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
    const TYPE_NAME: &'static str = "writecache";
    type Info = RawInfo;
}
impl fmt::Display for Writecache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            Kind::Ssd => 's',
            Kind::PersistentMemory => 'p',
        };
        write!(f, "{kind} {} {} {}", self.origin, self.cache, self.block_size)?;
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
    ///
    /// # Errors
    ///
    /// [`crate::Error::Usage`] if either watermark percentage exceeds
    /// `100`, if both are set and `high < low`, or if `block_size` is not
    /// a power of two or is below `512`.
    pub fn build(self) -> Result<Writecache, crate::Error> {
        if let Some(hw) = self.high_watermark_percent
            && hw > 100
        {
            return Err(crate::Error::Usage(format!(
                "writecache high_watermark must be <= 100, got {hw}"
            )));
        }
        if let Some(lw) = self.low_watermark_percent
            && lw > 100
        {
            return Err(crate::Error::Usage(format!(
                "writecache low_watermark must be <= 100, got {lw}"
            )));
        }
        // The kernel fills an unset watermark with its default (high 50,
        // low 45) and *always* checks high >= low — so resolve the effective
        // values before comparing, not only when both are set.
        let effective_high = self.high_watermark_percent.unwrap_or(DEFAULT_HIGH_WATERMARK);
        let effective_low = self.low_watermark_percent.unwrap_or(DEFAULT_LOW_WATERMARK);
        if effective_high < effective_low {
            return Err(crate::Error::Usage(format!(
                "writecache high_watermark ({effective_high}) must be >= low_watermark ({effective_low})"
            )));
        }
        if !self.block_size.is_power_of_two() || self.block_size < 512 {
            return Err(crate::Error::Usage(format!(
                "writecache block_size must be a power of two >= 512, got {}",
                self.block_size
            )));
        }
        Ok(Writecache {
            kind: self.kind,
            origin: self.origin,
            cache: self.cache,
            block_size: self.block_size,
            high_watermark_percent: self.high_watermark_percent,
            low_watermark_percent: self.low_watermark_percent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: Target + fmt::Display>(start: u64, length: u64, target: &T) -> String {
        let params = target.to_string();
        if params.is_empty() {
            format!("{start} {length} {}", T::TYPE_NAME)
        } else {
            format!("{start} {length} {} {params}", T::TYPE_NAME)
        }
    }

    #[test]
    fn writecache_renders_mode_and_optional_watermarks() {
        let t = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(90)
            .build()
            .expect("valid writecache");
        assert_eq!(line(0, 8192, &t), "0 8192 writecache s 252:1 252:2 4096 2 high_watermark 90");
    }

    #[test]
    fn writecache_renders_pmem_with_no_optional_args() {
        let t = Writecache::builder(
            Kind::PersistentMemory,
            DevId::new(252, 1),
            DevId::new(252, 2),
            4096,
        )
        .build()
        .expect("valid writecache");
        assert_eq!(line(0, 8192, &t), "0 8192 writecache p 252:1 252:2 4096 0");
    }

    #[test]
    fn writecache_renders_low_watermark_only() {
        let t = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .low_watermark_percent(20)
            .build()
            .expect("valid writecache");
        assert_eq!(line(0, 8192, &t), "0 8192 writecache s 252:1 252:2 4096 2 low_watermark 20");
    }

    #[test]
    fn writecache_renders_both_watermarks() {
        let t = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(90)
            .low_watermark_percent(20)
            .build()
            .expect("valid writecache");
        assert_eq!(
            line(0, 8192, &t),
            "0 8192 writecache s 252:1 252:2 4096 4 high_watermark 90 low_watermark 20"
        );
    }

    #[test]
    fn writecache_rejects_high_below_low() {
        let r = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(20)
            .low_watermark_percent(90)
            .build();
        assert!(matches!(r, Err(crate::Error::Usage(_))));
    }

    #[test]
    fn writecache_rejects_high_below_default_low_when_low_unset() {
        // low unset -> kernel default 45; high 40 < 45 must be rejected even
        // though only one watermark was supplied.
        let r = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(40)
            .build();
        assert!(matches!(r, Err(crate::Error::Usage(_))));
        // high 50 (== default low+) is fine.
        let ok = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(50)
            .build();
        assert!(ok.is_ok());
    }

    #[test]
    fn writecache_rejects_percent_over_100() {
        let r = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4096)
            .high_watermark_percent(101)
            .build();
        assert!(matches!(r, Err(crate::Error::Usage(_))));
    }

    #[test]
    fn writecache_rejects_bad_block_size() {
        // Not a power of two.
        let npot = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 4000).build();
        assert!(matches!(npot, Err(crate::Error::Usage(_))));
        // Below 512.
        let small = Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 256).build();
        assert!(matches!(small, Err(crate::Error::Usage(_))));
        // Valid: 512.
        assert!(
            Writecache::builder(Kind::Ssd, DevId::new(252, 1), DevId::new(252, 2), 512).build().is_ok()
        );
    }
}
