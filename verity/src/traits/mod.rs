// SPDX-License-Identifier: Apache-2.0

//! Verity operations grouped by I/O ecosystem.

/// Standard-library synchronous operations.
pub mod std;

/// Tokio asynchronous operations.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio;
