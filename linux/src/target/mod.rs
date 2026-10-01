// SPDX-License-Identifier: Apache-2.0

//! The target protocol and Linux device-mapper targets without a shared
//! on-disk format.

pub mod crypt;
mod empty;
mod protocol;
pub mod snapshot;
mod version;
pub mod zero;

pub use empty::Empty;
pub use protocol::{EncodeError, Parse, Target};
pub use version::Version;
