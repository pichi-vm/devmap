// SPDX-License-Identifier: Apache-2.0

//! Layer operation and endpoint traits grouped by I/O ecosystem.

/// Traits for standard-library synchronous I/O.
pub mod std;

/// Traits for Tokio asynchronous I/O.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio;
