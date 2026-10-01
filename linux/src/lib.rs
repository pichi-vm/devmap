// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod abi;
mod control;
mod dev_id;
pub mod device;
mod parse_error;
pub mod table;
pub mod target;

pub(crate) use abi::{header, uapi};

pub use control::Control;
pub use dev_id::DevId;
pub use parse_error::ParseError;

/// The primary handles are cheap to clone and safe to share across
/// threads; assert it at compile time so a future field addition can't
/// silently regress it.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Control>();
    assert_send_sync::<device::Device>();
};
