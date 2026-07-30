// SPDX-License-Identifier: Apache-2.0

//! The "trivial" real Linux device-mapper target types. Each is a struct
//! implementing [`crate::Target`]; construct one and hand it to
//! [`crate::Device::builder`]'s [`add`](crate::TableBuilder::add).

pub mod delay;
pub mod dust;
pub mod era;
pub mod error;
pub mod flakey;
pub mod integrity;
pub mod linear;
pub mod log_writes;
pub mod raid;
pub mod snapshot;
pub mod striped;
pub mod thin;
pub mod thin_pool;
pub mod unstriped;
pub mod verity;
pub mod writecache;
pub mod zero;
pub mod zoned;

pub use delay::Delay;
pub use dust::Dust;
pub use era::Era;
pub use error::Error;
pub use flakey::Flakey;
pub use integrity::Integrity;
pub use linear::Linear;
pub use log_writes::LogWrites;
pub use raid::Raid;
pub use snapshot::Snapshot;
pub use striped::Striped;
pub use thin::Thin;
pub use thin_pool::ThinPool;
pub use unstriped::Unstriped;
pub use verity::Verity;
pub use writecache::Writecache;
pub use zero::Zero;
pub use zoned::Zoned;
