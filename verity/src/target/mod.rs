// SPDX-License-Identifier: Apache-2.0

use crate::{KeyDescription, Options, Scheme, Shape, layout::Layout};
use devmap_core::{Target, parse::DevId};
use std::io;

mod codec;
mod info;
pub use info::Info;

/// A validated Linux dm-verity table description.
///
/// Construct through [`Options::target`]. The root must come from an
/// independently trusted source. Activate in a read-only table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerityTarget {
    scheme: Scheme,
    shape: Shape,
    // The signature is owned separately; options() constructs its borrowed view.
    options: Options<'static>,
    signature: Option<String>,
    data_dev: DevId,
    hash_dev: DevId,
    root: Vec<u8>,
    data_sectors: u64,
}

impl VerityTarget {
    /// Returns the accepted hashing choices.
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }
    /// Returns the accepted block geometry.
    pub const fn shape(&self) -> Shape {
        self.shape
    }
    /// Returns settings with any key description borrowed from this target.
    pub fn options(&self) -> Options<'_> {
        Options {
            root_hash_sig_key_desc: self.signature.as_deref().map(KeyDescription::validated),
            ..self.options
        }
    }
    /// Returns the data device.
    pub const fn data_dev(&self) -> DevId {
        self.data_dev
    }
    /// Returns the hash device.
    pub const fn hash_dev(&self) -> DevId {
        self.hash_dev
    }
    /// Borrows the externally supplied root digest.
    pub fn root_digest(&self) -> &[u8] {
        &self.root
    }
    /// Returns the full row length in 512-byte sectors.
    pub const fn data_sectors(&self) -> u64 {
        self.data_sectors
    }
}

impl Target for VerityTarget {
    const NAME: &'static str = "verity";
    type Table = Self;
    type Info = Info;
}

impl Options<'_> {
    /// Binds a scheme, shape, device IDs, and trusted root into a Linux target.
    ///
    /// Performs no I/O. The kernel checks device capacity and feature support
    /// on load; it authenticates data on reads.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` for an overflowing layout, incorrect root
    /// length, or incompatible options.
    ///
    /// ```
    /// use std::num::NonZeroU64;
    /// use devmap_core::parse::DevId;
    /// use devmap_verity::{Options, Scheme, Shape};
    ///
    /// # fn mapping(root: &[u8]) -> std::io::Result<()> {
    /// let target = Options::default().with_hash_start_block(0).target(
    ///     Scheme::default(),
    ///     Shape::new(NonZeroU64::new(128).unwrap()),
    ///     DevId::new(7, 0).unwrap(),
    ///     DevId::new(7, 1).unwrap(),
    ///     root,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn target(
        self,
        scheme: Scheme,
        shape: Shape,
        data_dev: DevId,
        hash_dev: DevId,
        root: &[u8],
    ) -> io::Result<VerityTarget> {
        let layout = Layout::new(&scheme, shape)?;
        self.validate(&layout)?;
        if root.len() != scheme.algorithm.digest_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "root digest length does not match the hash algorithm",
            ));
        }
        Ok(VerityTarget {
            scheme,
            shape,
            options: self.without_signature(),
            signature: self
                .root_hash_sig_key_desc
                .map(|description| description.as_ref().to_owned()),
            data_dev,
            hash_dev,
            root: root.into(),
            data_sectors: (layout.data_size / 512) as u64,
        })
    }
}
