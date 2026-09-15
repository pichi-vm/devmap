// SPDX-License-Identifier: Apache-2.0

//! Storage capabilities for standard-library and Tokio I/O types.

#[cfg(feature = "tokio")]
mod r#async;
#[cfg(target_os = "linux")]
mod linux;
mod sync;
