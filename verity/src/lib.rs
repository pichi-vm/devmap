// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::similar_names
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! Inspect dm-verity hash devices, format hash trees, and read authenticated data.
//!
//! [`Hashes`] opens a hash device independently of its data device or trusted
//! root. [`Header`] exposes validated metadata for inspection and Linux
//! activation. The crate does not activate kernel devices or store trusted roots.
//!
//! # Inspecting a hash device
//!
//! Header inspection and target descriptions need no hashing dependencies.
//! Disable default features to use them with only the shared core dependency.
//! Opening reads only the 512-byte record at byte zero:
//!
//! ```no_run
//! use std::fs::File;
//! use devmap_verity::{Hashes, traits::std::OpenHashes as _};
//!
//! # fn main() -> std::io::Result<()> {
//! let hashes = Hashes::open(File::open("hash.img")?)?;
//! let header = hashes.header();
//! println!("{} data blocks of {} bytes, {}", header.data_blocks(),
//!     header.data_block_size(), header.algorithm());
//! # Ok(())
//! # }
//! ```
//!
//! Import the operation traits from `traits::tokio` for asynchronous storage.
//! Method names and types stay the same:
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> std::io::Result<()> {
//! use devmap_verity::{Hashes, traits::tokio::OpenHashes as _};
//!
//! let hashes = Hashes::open(tokio::fs::File::open("hash.img").await?).await?;
//! println!("{}", hashes.header().algorithm());
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "tokio"))]
//! # fn main() {}
//! ```
//!
//! Opening validates supported field values, canonical zero padding inside the
//! record, and layout arithmetic. It does not read block padding or tree
//! contents, inspect endpoint geometry, or authenticate anything. Known
//! algorithm names remain valid even when their implementations are disabled;
//! unknown names and format versions are rejected.
//!
//! # Formatting and authenticated reading
//!
//! Enabling any hash family provides `Formatter` and `Verity`. This example
//! uses the default SHA-256 algorithm:
//!
//! ```
//! # #[cfg(feature = "sha2")]
//! # fn main() -> std::io::Result<()> {
//! use std::io::{Cursor, Read};
//! use std::num::NonZeroU32;
//! use devmap_verity::{Formatter, Hashes, Verity,
//!     traits::std::{Format as _, Open as _, OpenHashes as _, Scale as _}};
//!
//! let block_size = NonZeroU32::new(4096).unwrap();
//! let bytes = vec![0x5a; 8192];
//! let data = Cursor::new(&bytes).scale_to(block_size)?;
//! let mut output = Cursor::new(Vec::new()).scale_to(block_size)?;
//! let root = Formatter::new([7; 16]).format(data, &mut output)?;
//!
//! let hashes = Hashes::open(output)?;
//! let mut volume = Verity::open(Cursor::new(bytes), hashes, &root)?;
//! let mut first = [0; 16];
//! volume.read_exact(&mut first)?;
//! assert_eq!(first, [0x5a; 16]);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "sha2"))]
//! # fn main() {}
//! ```
//!
//! Formatting derives block sizes and the protected extent from endpoint
//! geometry, consumes exactly that input extent, and writes from hash-device
//! byte zero. It returns the root only after flushing completed output.
//! Flushing does not guarantee persistence; retain the output by passing a
//! mutable reference and use `SyncData` before kernel activation or whenever
//! persistence is required. Keep the returned root through an independently
//! trusted channel.
//!
//! Opening a `Verity` view checks endpoint geometry, capacity, and root-digest
//! length, but does not hash. Each complete data block is authenticated against
//! the trusted root before any of its bytes are returned. Corruption and a
//! disabled hashing implementation therefore fail during reading, not opening.
//! Unread blocks have not been authenticated. Copy the complete view to an I/O
//! sink when the entire protected extent must be checked.
//!
//! Backing contents must remain unchanged while opened. Pass an adapter for
//! caching or a zero-based region for an embedded device; offsets inside this
//! crate always refer to that endpoint's byte zero. A header reference remains
//! available during pending I/O. Cancelling an asynchronous open or format can
//! advance streams and drops owned endpoints; formatting can leave partial
//! output. A cancelled authenticated read resumes on the next read; seeking
//! meanwhile reports [`std::io::ErrorKind::WouldBlock`].
//!
//! # Preparing kernel activation
//!
//! [`dm::Builder::from`] copies format fields from [`Hashes::header`]. Its
//! [`build`](dm::Builder::build) method takes the data and hash device IDs and
//! the independently trusted root digest. Neither opening the header nor
//! building a target requires a hashing implementation.
//!
//! Pass the resulting [`dm::VerityTarget`] to a backend such as `devmap-linux`.
//! Set the table read-only and use [`dm::VerityTarget::data_sectors`] for a full-size
//! row, then load the table and resume the device. For an embedded header, open
//! its zero-based region and set [`dm::Builder::header_offset_bytes`] to its
//! physical byte offset in the kernel's hash device.
//!
//! # Cargo features
//!
//! - `sha2` is enabled by default and implements SHA-224/256/384/512.
//! - `sha1`, `ripemd`, `whirlpool`, `sha3`, `streebog`, `sm3`, and
//!   `blake2` enable their respective hash families.
//! - `tokio` adds asynchronous operations, including metadata-only opening;
//!   it does not enable any hash implementation.
//!
//! Disabling all default features leaves synchronous metadata inspection and
//! target descriptions.
//! Every hash-family feature also enables `digest`, the shared hash interface.

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
mod superblock;
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
pub use superblock::Formatter;
pub use superblock::{Algorithm, HashType, Header};

/// Device-mapper target parameters, header conversions, and runtime status.
pub mod dm;
