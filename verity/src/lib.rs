// SPDX-License-Identifier: Apache-2.0

//! Read dm-verity v1 superblocks and write dm-verity hash trees.
//!
//! A hash device has this layout:
//!
//! ```text
//! | 512-byte superblock | padding to hash-block size | hash tree |
//! ```
//!
//! [`Unverified`] contains the 512 bytes stored on disk. Convert it to
//! [`Verified`] to validate those bytes. Convert a [`Verified`] value back to
//! [`Unverified`] before writing it. [`TreeWriter`] writes the hash tree for a
//! separate data device.
//!
//! Synchronous and asynchronous I/O use the same crate types and follow the
//! same steps. Only the I/O traits differ. Enable `futures-io` for asynchronous
//! tree writing.
//!
//! This crate does not create or activate device-mapper devices.
//!
//! # Reading
//!
//! Read an [`Unverified`] value, convert it to [`Verified`], then skip
//! [`Verified::padding`]. The reader will then be at the start of the hash tree.
//!
//! ## Synchronous
//!
//! ```
//! use devmap_verity::{Unverified, Verified};
//! use std::io::{self, Read};
//!
//! fn read_superblock<R: Read>(mut reader: R) -> io::Result<(Verified, R)> {
//!     // Read the 512-byte superblock.
//!     let mut bytes = Unverified::default();
//!     reader.read_exact(bytes.as_mut())?;
//!
//!     // Validate its fields.
//!     let superblock = Verified::try_from(bytes)?;
//!
//!     // Skip the rest of the hash block.
//!     let padding = superblock.padding();
//!     let read = io::copy(&mut reader.by_ref().take(padding), &mut io::sink())?;
//!     if read != padding {
//!         return Err(io::ErrorKind::UnexpectedEof.into());
//!     }
//!
//!     Ok((superblock, reader))
//! }
//! ```
//!
//! ## Asynchronous
//!
//! This version uses the same crate types and follows the same steps:
//!
//! ```
//! use devmap_verity::{Unverified, Verified};
//! use futures::io::{self as futures_io, AsyncRead, AsyncReadExt};
//! use std::io;
//!
//! async fn read_superblock<R>(mut reader: R) -> io::Result<(Verified, R)>
//! where
//!     R: AsyncRead + Unpin,
//! {
//!     // Read the 512-byte superblock.
//!     let mut bytes = Unverified::default();
//!     reader.read_exact(bytes.as_mut()).await?;
//!
//!     // Validate its fields.
//!     let superblock = Verified::try_from(bytes)?;
//!
//!     // Skip the rest of the hash block.
//!     let padding = superblock.padding();
//!     let read = futures_io::copy(
//!         &mut (&mut reader).take(padding),
//!         &mut futures_io::sink(),
//!     )
//!     .await?;
//!     if read != padding {
//!         return Err(io::ErrorKind::UnexpectedEof.into());
//!     }
//!
//!     Ok((superblock, reader))
//! }
//! ```
//!
//! # Writing
//!
//! Build a [`Verified`] value, write its [`Unverified`] form and padding, then
//! copy the data-device contents into its [`TreeWriter`]. Flush the tree writer
//! before calling [`TreeWriter::digest`]. A partial final data block is padded
//! with zeroes. The backing data device must contain the same padding so that
//! its size is at least `data_blocks * data_block_size`. Dropping a tree writer
//! does not flush it.
//!
//! The examples use the builder defaults: SHA-256, normal hash layout, and
//! 4096-byte data and hash blocks. Use a new UUID and salt for each persistent
//! image.
//!
//! ## Synchronous
//!
//! ```
//! use devmap_verity::{TreeWriter, Unverified, Verified};
//! use std::io::{self, Read, Seek, SeekFrom, Write};
//! use std::num::NonZeroU64;
//!
//! fn write_hash_device<R, W>(
//!     mut contents: R,
//!     mut hash_device: W,
//!     uuid: [u8; 16],
//!     salt: &[u8],
//! ) -> io::Result<(W, Vec<u8>)>
//! where
//!     R: Read + Seek,
//!     W: Write + Seek,
//! {
//!     const DATA_BLOCK_SIZE: u32 = 4096;
//!
//!     // Count the data blocks from the unread input.
//!     let start = contents.stream_position()?;
//!     let end = contents.seek(SeekFrom::End(0))?;
//!     contents.seek(SeekFrom::Start(start))?;
//!     let length = end
//!         .checked_sub(start)
//!         .ok_or(io::ErrorKind::InvalidInput)?;
//!     if length % u64::from(DATA_BLOCK_SIZE) != 0 {
//!         return Err(io::Error::new(
//!             io::ErrorKind::InvalidInput,
//!             "the data device must end on a data-block boundary",
//!         ));
//!     }
//!     let data_blocks = NonZeroU64::new(length / u64::from(DATA_BLOCK_SIZE))
//!         .ok_or(io::ErrorKind::InvalidInput)?;
//!
//!     // Build the superblock.
//!     let superblock = Verified::builder()
//!         .salt(salt)?
//!         .build(uuid, data_blocks)?;
//!
//!     // Write the superblock and its padding.
//!     let bytes = Unverified::from(&superblock);
//!     hash_device.write_all(bytes.as_ref())?;
//!     io::copy(
//!         &mut io::repeat(0).take(superblock.padding()),
//!         &mut hash_device,
//!     )?;
//!
//!     // Write the tree and finish the final data block.
//!     let digest = {
//!         let mut tree = TreeWriter::new(&mut hash_device, superblock)?;
//!         io::copy(&mut contents, &mut tree)?;
//!         tree.flush()?;
//!
//!         // The root digest is available after the final flush.
//!         tree.digest()?.to_vec()
//!     };
//!
//!     Ok((hash_device, digest))
//! }
//! ```
//!
//! ## Asynchronous
//!
//! Enable the `futures-io` feature for asynchronous tree writing.
//!
//! ```
//! use devmap_verity::{TreeWriter, Unverified, Verified};
//! use futures::io::{
//!     self as futures_io, AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
//!     AsyncWriteExt,
//! };
//! use std::io::{self, SeekFrom};
//! use std::num::NonZeroU64;
//!
//! # #[cfg(feature = "futures-io")]
//! async fn write_hash_device<R, W>(
//!     mut contents: R,
//!     mut hash_device: W,
//!     uuid: [u8; 16],
//!     salt: &[u8],
//! ) -> io::Result<(W, Vec<u8>)>
//! where
//!     R: AsyncRead + AsyncSeek + Unpin,
//!     W: AsyncWrite + AsyncSeek + Unpin,
//! {
//!     const DATA_BLOCK_SIZE: u32 = 4096;
//!
//!     // Count the data blocks from the unread input.
//!     let start = contents.stream_position().await?;
//!     let end = contents.seek(SeekFrom::End(0)).await?;
//!     contents.seek(SeekFrom::Start(start)).await?;
//!     let length = end
//!         .checked_sub(start)
//!         .ok_or(io::ErrorKind::InvalidInput)?;
//!     if length % u64::from(DATA_BLOCK_SIZE) != 0 {
//!         return Err(io::Error::new(
//!             io::ErrorKind::InvalidInput,
//!             "the data device must end on a data-block boundary",
//!         ));
//!     }
//!     let data_blocks = NonZeroU64::new(length / u64::from(DATA_BLOCK_SIZE))
//!         .ok_or(io::ErrorKind::InvalidInput)?;
//!
//!     // Build the superblock.
//!     let superblock = Verified::builder()
//!         .salt(salt)?
//!         .build(uuid, data_blocks)?;
//!
//!     // Write the superblock and its padding.
//!     let bytes = Unverified::from(&superblock);
//!     hash_device.write_all(bytes.as_ref()).await?;
//!     futures_io::copy(
//!         &mut futures_io::repeat(0).take(superblock.padding()),
//!         &mut hash_device,
//!     )
//!     .await?;
//!
//!     // Write the tree and finish the final data block.
//!     let digest = {
//!         let mut tree = TreeWriter::new(&mut hash_device, superblock)?;
//!         futures_io::copy(&mut contents, &mut tree).await?;
//!         tree.flush().await?;
//!
//!         // The root digest is available after the final flush.
//!         tree.digest()?.to_vec()
//!     };
//!
//!     Ok((hash_device, digest))
//! }
//! ```
//!
//! # Hash algorithm features
//!
//! The default feature is `sha2`. [`Algorithm`] and superblock validation
//! support every algorithm in the table. Writing a tree requires the matching
//! feature. The names in the table are the Linux names stored in a superblock.
//!
//! | Feature     | Algorithms                                     |
//! | ----------- | ---------------------------------------------- |
//! | `sha1`      | `sha1`                                         |
//! | `sha2`      | `sha224`, `sha256`, `sha384`, `sha512`         |
//! | `ripemd`    | `rmd160`                                       |
//! | `whirlpool` | `wp512`                                        |
//! | `sha3`      | `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512` |
//! | `streebog`  | `streebog256`, `streebog512`                   |
//! | `sm3`       | `sm3`                                          |
//! | `blake2`    | `blake2b-160`, `blake2b-256`, `blake2b-384`, `blake2b-512`, `blake2s-128`, `blake2s-160`, `blake2s-224`, `blake2s-256` |

// Lint posture for a byte-format implementation. The dm-verity encoding is
// pervasive block-index and size arithmetic across usize/u32/u16/u64; the
// narrowing casts are bounded by the validated block sizes and the whole
// output is cross-checked byte-for-byte against `veritysetup format`, so the
// cast lints are noise. Format docs name many bare identifiers (SHA256, NUL,
// TOP-DOWN) where backticks add nothing.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::similar_names
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod superblock;
mod tree;

pub use superblock::{Algorithm, Builder, HashType, Unverified, Verified};
pub use tree::TreeWriter;
