// SPDX-License-Identifier: Apache-2.0

//! The `thin` target: a single thin-provisioned volume backed by a
//! thin-pool.

use std::fmt;

use crate::DevId;
use crate::table::{RawInfo, Target};

/// One provisioned volume inside a [`crate::targets::ThinPool`]. `dev_id` must already
/// exist in the pool (created via a `create_thin`/`create_snap`
/// message — see [`crate::Device::message`]) before this table line can
/// be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Thin {
    pool: DevId,
    dev_id: u32,
    external_origin: Option<DevId>,
}
impl Thin {
    /// The largest thin device id the kernel accepts: `(1 << 24) - 1`.
    const MAX_DEV_ID: u32 = 16_777_215;

    /// Construct a [`Thin`].
    ///
    /// # Errors
    ///
    /// [`crate::Error::Usage`] if `dev_id` exceeds `16_777_215`
    /// (the kernel's `MAX_DEV_ID`).
    pub fn new(
        pool: DevId,
        dev_id: u32,
        external_origin: Option<DevId>,
    ) -> Result<Self, crate::Error> {
        if dev_id > Self::MAX_DEV_ID {
            return Err(crate::Error::Usage(format!(
                "thin dev_id must be <= {}, got {dev_id}",
                Self::MAX_DEV_ID
            )));
        }
        Ok(Thin {
            pool,
            dev_id,
            external_origin,
        })
    }

    /// The backing thin-pool device.
    #[must_use]
    pub fn pool(&self) -> DevId {
        self.pool
    }
    /// The thin device id within the pool.
    #[must_use]
    pub fn dev_id(&self) -> u32 {
        self.dev_id
    }
    /// The external origin device, if any.
    #[must_use]
    pub fn external_origin(&self) -> Option<DevId> {
        self.external_origin
    }
}
impl Target for Thin {
    const TYPE_NAME: &'static str = "thin";
    type Info = RawInfo;
}
impl fmt::Display for Thin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.pool, self.dev_id)?;
        if let Some(external_origin) = self.external_origin {
            write!(f, " {external_origin}")?;
        }
        Ok(())
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
    fn thin_renders_without_external_origin() {
        let t = Thin::new(DevId::new(252, 1), 7, None).expect("valid thin");
        assert_eq!(line(0, 1024, &t), "0 1024 thin 252:1 7");
    }

    #[test]
    fn thin_renders_with_external_origin() {
        let t = Thin::new(DevId::new(252, 1), 7, Some(DevId::new(252, 9))).expect("valid thin");
        assert_eq!(line(0, 1024, &t), "0 1024 thin 252:1 7 252:9");
    }

    #[test]
    fn thin_rejects_dev_id_over_max() {
        assert!(matches!(
            Thin::new(DevId::new(252, 1), 16_777_216, None),
            Err(crate::Error::Usage(_))
        ));
    }

    #[test]
    fn thin_accepts_boundary_dev_id() {
        assert!(Thin::new(DevId::new(252, 1), 16_777_215, None).is_ok());
    }
}
