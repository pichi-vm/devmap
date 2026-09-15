// SPDX-License-Identifier: Apache-2.0

//! Storage geometry, persistence, and adapter construction.
//!
//! Choose `std` for synchronous I/O or `tokio` for Tokio streams.

/// Traits for standard-library synchronous I/O.
pub mod std;

/// Traits for Tokio asynchronous I/O.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio;
