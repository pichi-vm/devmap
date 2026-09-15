// SPDX-License-Identifier: Apache-2.0

//! Construction and formatting operations.
//!
//! Choose `std` for synchronous I/O or `tokio` for Tokio streams.

pub mod std;

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio;
