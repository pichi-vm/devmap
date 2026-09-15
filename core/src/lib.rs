// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! Shared storage adapters and device-mapper target descriptions.
//!
//! Use ordinary byte I/O on storage with explicit block geometry. This crate
//! supplies the common interfaces; on-disk formats and kernel activation
//! belong to the format crates and `devmap-linux`.
//!
//! # Storage
//!
//! Import [`traits::std`] to choose a logical block size or a bounded view,
//! then read and write through the usual I/O traits:
//!
//! ```
//! use devmap_core::traits::std::{Scale as _, Slice as _};
//! use std::io::{Cursor, Read};
//! use std::num::NonZeroU32;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut region = Cursor::new(vec![7; 8192])
//!     .scale_to(NonZeroU32::new(4096).unwrap())?
//!     .slice(1..2)?;
//! let mut block = [0; 4096];
//! region.read_exact(&mut block)?;
//! assert_eq!(block, [7; 4096]);
//! # Ok(())
//! # }
//! ```
//!
//! # Device mapper
//!
//! Format crates implement [`Target`] to describe mappings that `devmap-linux`
//! can load.
//! [`parse`] supplies their shared field values and errors.
//!
//! # Cargo features
//!
//! No default features. `tokio` enables `traits::tokio` and asynchronous I/O
//! on the same adapters.

pub mod parse;
mod region;
mod scaled;
mod storage;
mod target;
pub mod traits;

pub use region::Region;
pub use scaled::Scaled;
pub use target::Target;
