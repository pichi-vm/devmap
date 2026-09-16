// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::similar_names
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! Inspect dm-verity metadata, build hash trees, and read authenticated data.
//!
//! [`Hashes`] opens metadata independently of the data device. With hashing
//! enabled, [`Scheme`] formats hash devices and [`Options`] opens userspace
//! verification. [`VerityTarget`] describes a Linux mapping; activation belongs
//! to a backend such as `devmap-linux`.
//!
//! Reading a header does not authenticate data. Verification requires a root
//! digest from an independently trusted source.
//!
//! # Inspecting a hash device
//!
//! Import the operation traits from [`traits::std`] for standard I/O:
//!
//! ```no_run
//! use std::fs::File;
//! use devmap_verity::{Hashes, traits::std::OpenHashes as _};
//!
//! # fn main() -> std::io::Result<()> {
//! let hashes = Hashes::open(File::open("hash.img")?)?;
//! println!("{}", hashes.scheme().algorithm);
//! # Ok(())
//! # }
//! ```
//!
//! # Cargo features
//!
//! Disable default features for metadata inspection and target descriptions
//! without hashing dependencies.
//!
//! - `sha2` is enabled by default.
//! - `sha1`, `sha3`, `ripemd`, `whirlpool`, `streebog`, `sm3`, and `blake2`
//!   enable other hash families.
//! - `tokio` provides matching asynchronous operations through `traits::tokio`;
//!   it does not enable hashing.

mod block_size;
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
mod device;
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
mod format;
mod hashes;
mod layout;
mod options;
mod scheme;
mod shape;
mod superblock;
mod target;
pub mod traits;
#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
mod tree;

#[cfg(any(
    feature = "sha1",
    feature = "sha2",
    feature = "sha3",
    feature = "ripemd",
    feature = "whirlpool",
    feature = "streebog",
    feature = "sm3",
    feature = "blake2"
))]
pub use device::Verity;
pub use hashes::Hashes;

pub use block_size::BlockSize;
pub use options::{CorruptionPolicy, Fec, IoErrorPolicy, KeyDescription, Options};
pub use scheme::{Algorithm, HashType, Scheme};
pub use shape::Shape;
pub use target::{Info, VerityTarget};
