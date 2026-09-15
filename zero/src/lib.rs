// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! Zero-filled storage for userspace and Linux device-mapper.
//!
//! Use [`Zero`] as a finite source of zero bytes. [`ZeroTarget`] describes a
//! kernel mapping; a backend such as `devmap-linux` handles activation.
//!
//! ```
//! use devmap_zero::Zero;
//! use std::io::Read;
//!
//! # fn main() -> std::io::Result<()> {
//! let mut source = Zero::new(4);
//! let mut bytes = [1; 4];
//! source.read_exact(&mut bytes)?;
//! assert_eq!(bytes, [0; 4]);
//! # Ok(())
//! # }
//! ```
//!
//! # Cargo features
//!
//! No default features. `tokio` enables asynchronous I/O on [`Zero`].

mod target;
mod zero;

pub use target::ZeroTarget;
pub use zero::Zero;
