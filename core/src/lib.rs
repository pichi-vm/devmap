// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]

//! Shared block-device interfaces and byte-oriented adapters.
//!
//! [`ReadBlocks`] and [`WriteBlocks`] describe const-sized random-access block
//! devices. [`DynReadBlocks`] and [`DynWriteBlocks`] expose the same operations
//! after the block size becomes a runtime property. [`ByteCursor`] uses the
//! runtime-sized traits, so its type has no block-size parameter. [`Runtime`]
//! adapts another const-sized implementation when it does not provide the
//! runtime-sized traits directly.
//!
//! [`BlockIo`] adapts bounded, seekable byte storage to block I/O. [`Zero`]
//! provides an unbounded zero-filled device that discards writes, and
//! [`Region`] gives a block device a bounded view.
//!
//! Enable `futures-io` to use the same adapters with asynchronous I/O.
//!
//! ```
//! use devmap_core::{ByteCursor, Region, Zero};
//! use std::io::{Read, Seek, SeekFrom};
//!
//! # fn main() -> std::io::Result<()> {
//! // Give the zero device a two-block address range.
//! let blocks = Region::<_, 512>::new(Zero, 0, 2)?;
//!
//! // Access that range as a 1024-byte stream.
//! let mut bytes = ByteCursor::new(blocks)?;
//! bytes.seek(SeekFrom::Start(510))?;
//! let mut output = [1; 4];
//! bytes.read_exact(&mut output)?;
//! assert_eq!(output, [0; 4]);
//! # Ok(())
//! # }
//! ```

mod count;
mod cursor;
mod io;
mod read;
mod region;
mod runtime;
mod size;
mod write;
mod zero;

pub use count::BlockCount;
pub use cursor::ByteCursor;
pub use io::BlockIo;
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub use read::{AsyncReadBlocks, DynAsyncReadBlocks};
pub use read::{DynReadBlocks, ReadBlocks};
pub use region::Region;
pub use runtime::Runtime;
pub use size::BlockSize;
#[cfg(feature = "futures-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "futures-io")))]
pub use write::{AsyncWriteBlocks, DynAsyncWriteBlocks};
pub use write::{DynWriteBlocks, WriteBlocks};
pub use zero::Zero;
