// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs::File, io, sync::Arc};

use zerocopy::{FromBytes, IntoBytes};

use crate::DevId;
use crate::control::target_version;
use crate::header::DmHeader;
use crate::target::{Target, Version};
use crate::uapi::{DM_MAX_TYPE_NAME, DM_TABLE_LOAD, DM_TARGET_SPEC_SIZE, dm_target_spec_raw};

use super::check_version;

/// A streaming builder for `DM_TABLE_LOAD`.
///
/// Each [`add`](Self::add) renders a target directly into one growing buffer.
/// Finish with [`load`](Self::load). Obtain a builder from
/// [`Device::builder`](super::Device::builder).
#[derive(Debug)]
pub struct Builder {
    control: Arc<File>,
    versions: HashMap<String, Version>,
    buf: Vec<u8>,
    count: u32,
    last_spec_off: Option<usize>,
}

impl Builder {
    pub(super) fn new(control: Arc<File>, dev: DevId) -> Self {
        let mut buf = Vec::with_capacity(DmHeader::SIZE + 256);
        buf.extend_from_slice(DmHeader::by_dev(u64::from(dev)).as_bytes());
        Self {
            control,
            versions: HashMap::new(),
            buf,
            count: 0,
            last_spec_off: None,
        }
    }

    /// Load the table **read-only** (sets `DM_READONLY_FLAG` on the
    /// `DM_TABLE_LOAD` header, which sets the table's mode). Required for
    /// dm-verity — it refuses a writable table with `-EINVAL` "Device must be
    /// readonly" — and used for read-only dm-snapshot composition. Call any
    /// time before [`load`](Self::load).
    // The `mut_from_prefix` expect never fires: the buffer always begins with
    // a `DmHeader` (written in `new`).
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn read_only(mut self) -> Self {
        let (header, _) =
            DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
        let header: &mut DmHeader = header;
        header.set_readonly();
        self
    }

    /// Append a target mapping sectors `[start, start + length)`.
    ///
    /// # Errors
    ///
    /// `Unsupported` if the target cannot encode the installed version;
    /// `InvalidInput` if `T::NAME` is invalid or the encoded parameters
    /// contain an interior NUL.
    // Table buffers never approach u32::MAX; the kernel's own fields are u32.
    // `target` is taken by value: the builder consumes its encoded row.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add<T: Target>(mut self, start: u64, length: u64, target: T) -> io::Result<Self> {
        Self::check_name(T::NAME)?;
        let version = self.resolve_version(T::NAME, target_version)?;
        let params = target.encode(version).map_err(|error| {
            io::Error::new(io::ErrorKind::Unsupported, format!("{}: {error}", T::NAME))
        })?;
        self.push_row(start, length, T::NAME, &params)
    }

    fn resolve_version(
        &mut self,
        name: &str,
        query: impl FnOnce(&File, &str) -> io::Result<Version>,
    ) -> io::Result<Version> {
        if let Some(version) = self.versions.get(name) {
            return Ok(*version);
        }
        let version = query(&self.control, name)?;
        self.versions.insert(name.to_owned(), version);
        Ok(version)
    }

    fn check_name(type_name: &str) -> io::Result<()> {
        let name = type_name.as_bytes();
        if name.is_empty()
            || name.len() >= DM_MAX_TYPE_NAME
            || name.iter().any(|b| *b == 0 || b.is_ascii_whitespace())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid dm target type name: {type_name:?}"),
            ));
        }
        Ok(())
    }

    /// Append a validated target row to the ioctl buffer.
    // Table buffers never approach u32::MAX; the kernel's own fields are u32.
    #[allow(clippy::cast_possible_truncation)]
    fn push_row(
        mut self,
        start: u64,
        length: u64,
        type_name: &str,
        params: &str,
    ) -> io::Result<Self> {
        Self::check_name(type_name)?;
        let name = type_name.as_bytes();
        if params.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("target {type_name} params contain an interior NUL"),
            ));
        }

        let spec_off = self.buf.len();
        if let Some(prev) = self.last_spec_off {
            // Write-side `next`: byte offset from the previous spec's start
            // to this one.
            let delta = (spec_off - prev) as u32;
            self.buf[prev + 20..prev + 24].copy_from_slice(&delta.to_ne_bytes());
        }

        let mut target_type = [0u8; DM_MAX_TYPE_NAME];
        target_type[..name.len()].copy_from_slice(name);
        let spec = dm_target_spec_raw {
            sector_start: start,
            length,
            status: 0,
            next: 0,
            target_type,
        };
        self.buf.extend_from_slice(spec.as_bytes());

        self.buf.extend_from_slice(params.as_bytes());
        self.buf.push(0);
        let block = DM_TARGET_SPEC_SIZE + params.len() + 1;
        self.buf.resize(spec_off + block.next_multiple_of(8), 0);

        self.last_spec_off = Some(spec_off);
        self.count += 1;
        Ok(self)
    }

    /// Issue `DM_TABLE_LOAD`, staging the accumulated table into the device's
    /// inactive slot. Activate it with [`super::Device::resume`].
    // The `mut_from_prefix` expects never fire: the buffer always begins with
    // a `DmHeader` (written in `new`), so this is not a real panic path.
    #[allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]
    pub fn load(mut self) -> io::Result<()> {
        let total = self.buf.len() as u32;
        {
            let (header, _) =
                DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
            let header: &mut DmHeader = header;
            header.set_data_size(total);
            header.set_target_count(self.count);
        }
        let (header, _) =
            DmHeader::mut_from_prefix(&mut self.buf).expect("buf begins with a DmHeader");
        let header: &mut DmHeader = header;
        DM_TABLE_LOAD.ioctl(&*self.control, header)?;
        check_version(header)
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test fixtures are tiny
mod tests {
    use super::*;
    use crate::target::zero::ZeroTarget;

    fn dummy_control() -> Arc<File> {
        Arc::new(File::open("/dev/null").expect("/dev/null always exists"))
    }

    fn builder(dev: DevId) -> Builder {
        let mut builder = Builder::new(dummy_control(), dev);
        let version = Version::from([1, 0, 0]);
        for name in ["zero", "nul-target", "custom-target", "0123456789abcde"] {
            builder.versions.insert(name.to_owned(), version);
        }
        builder
    }

    #[test]
    fn version_lookup_is_cached_by_target_name() {
        let mut builder = Builder::new(dummy_control(), DevId::new(252, 1).unwrap());
        let expected = Version::from([1, 2, 3]);
        assert_eq!(
            builder
                .resolve_version("zero", |_, _| Ok(expected))
                .unwrap(),
            expected
        );
        assert_eq!(
            builder
                .resolve_version("zero", |_, _| panic!("second lookup must use cache"))
                .unwrap(),
            expected
        );
        assert_eq!(builder.versions.len(), 1);
    }

    #[test]
    fn unsupported_target_version_is_rejected() {
        let mut builder = builder(DevId::new(252, 1).unwrap());
        builder
            .versions
            .insert("zero".to_owned(), Version::from([2, 0, 0]));
        let result = builder.add(0, 8, ZeroTarget);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported));
    }

    #[test]
    fn buf_for_zero_target_has_correct_layout() {
        let builder = builder(DevId::new(252, 5).unwrap())
            .add(0, 8, ZeroTarget)
            .expect("add zero");
        assert_eq!(builder.buf.len(), DmHeader::SIZE + 48);
    }

    #[test]
    fn read_only_sets_the_readonly_flag_on_the_header() {
        let builder = builder(DevId::new(252, 5).unwrap())
            .read_only()
            .add(0, 8, ZeroTarget)
            .expect("add zero");
        let (header, _) =
            DmHeader::ref_from_prefix(&builder.buf).expect("buf begins with a DmHeader");
        let header: &DmHeader = header;
        assert_eq!(
            header.flags() & crate::uapi::DM_READONLY_FLAG,
            crate::uapi::DM_READONLY_FLAG
        );
    }

    #[test]
    fn default_builder_does_not_set_readonly() {
        let builder = builder(DevId::new(252, 5).unwrap())
            .add(0, 8, ZeroTarget)
            .expect("add zero");
        let (header, _) =
            DmHeader::ref_from_prefix(&builder.buf).expect("buf begins with a DmHeader");
        let header: &DmHeader = header;
        assert_eq!(header.flags() & crate::uapi::DM_READONLY_FLAG, 0);
    }

    #[test]
    fn buf_for_linear_target_has_correct_layout_and_params() {
        let builder = builder(DevId::new(252, 9).unwrap())
            .push_row(0, 1024, "linear", "252:5 0")
            .expect("add linear");
        let params = "252:5 0";
        let aligned = (DM_TARGET_SPEC_SIZE + params.len() + 1).next_multiple_of(8);
        assert_eq!(builder.buf.len(), DmHeader::SIZE + aligned);

        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(
            &builder.buf[param_start..param_start + params.len()],
            params.as_bytes()
        );
        assert_eq!(builder.buf[param_start + params.len()], 0);
        let type_field = &builder.buf[DmHeader::SIZE + 24..DmHeader::SIZE + 24 + DM_MAX_TYPE_NAME];
        assert_eq!(&type_field[..6], b"linear");
    }

    #[test]
    fn buf_for_three_target_table_chains_specs_relative_to_current() {
        let builder = builder(DevId::new(252, 9).unwrap())
            .add(0, 8, ZeroTarget)
            .and_then(|builder| builder.push_row(8, 1024, "linear", "252:5 5"))
            .and_then(|builder| builder.push_row(1032, 8, "error", ""))
            .expect("build three-target table");

        let zero_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        let linear_aligned = (DM_TARGET_SPEC_SIZE + "252:5 5".len() + 1).next_multiple_of(8);
        let error_aligned = (DM_TARGET_SPEC_SIZE + 1).next_multiple_of(8);
        assert_eq!(
            builder.buf.len(),
            DmHeader::SIZE + zero_aligned + linear_aligned + error_aligned
        );

        let spec0 = DmHeader::SIZE;
        let spec1 = spec0 + zero_aligned;
        let spec2 = spec1 + linear_aligned;
        let next0 = u32::from_ne_bytes(builder.buf[spec0 + 20..spec0 + 24].try_into().unwrap());
        let next1 = u32::from_ne_bytes(builder.buf[spec1 + 20..spec1 + 24].try_into().unwrap());
        let next2 = u32::from_ne_bytes(builder.buf[spec2 + 20..spec2 + 24].try_into().unwrap());
        assert_eq!(next0, zero_aligned as u32);
        assert_eq!(next1, linear_aligned as u32);
        assert_eq!(next2, 0);
        assert_eq!(builder.count, 3);
    }

    struct NulTarget;

    impl Target for NulTarget {
        const NAME: &'static str = "nul-target";
        type Table = String;
        type Info = String;

        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok("before\0after".to_owned())
        }
    }

    #[test]
    fn builder_rejects_an_interior_nul_in_params() {
        let result = builder(DevId::new(252, 1).unwrap()).add(0, 8, NulTarget);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }

    struct BadNameTarget;

    impl Target for BadNameTarget {
        const NAME: &'static str = "bad name";
        type Table = String;
        type Info = String;

        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok(String::new())
        }
    }

    #[test]
    fn builder_rejects_an_invalid_type_name() {
        let result = builder(DevId::new(252, 1).unwrap()).add(0, 8, BadNameTarget);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }

    struct CustomTarget;

    impl Target for CustomTarget {
        const NAME: &'static str = "custom-target";
        type Table = String;
        type Info = String;

        fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
            Ok("1 2 3".to_owned())
        }
    }

    #[test]
    fn an_out_of_tree_target_can_be_added() {
        let builder = builder(DevId::new(252, 1).unwrap())
            .add(0, 8, CustomTarget)
            .expect("add custom target");
        let params = "1 2 3";
        let type_field = &builder.buf[DmHeader::SIZE + 24..DmHeader::SIZE + 24 + DM_MAX_TYPE_NAME];
        assert_eq!(&type_field[..CustomTarget::NAME.len()], b"custom-target");
        let param_start = DmHeader::SIZE + DM_TARGET_SPEC_SIZE;
        assert_eq!(
            &builder.buf[param_start..param_start + params.len()],
            params.as_bytes()
        );
        assert_eq!(builder.buf[param_start + params.len()], 0);
    }

    struct EmptyName;
    struct SixteenByteName;
    struct FifteenByteName;

    macro_rules! empty_target {
        ($type:ty, $name:literal) => {
            impl Target for $type {
                const NAME: &'static str = $name;
                type Table = String;
                type Info = String;

                fn encode(&self, _: Version) -> Result<String, crate::target::EncodeError> {
                    Ok(String::new())
                }
            }
        };
    }

    empty_target!(EmptyName, "");
    empty_target!(SixteenByteName, "0123456789abcdef");
    empty_target!(FifteenByteName, "0123456789abcde");

    #[test]
    fn builder_rejects_empty_and_overlong_names_but_accepts_15_bytes() {
        let dev = DevId::new(252, 1).unwrap();
        assert!(matches!(
            builder(dev).add(0, 8, EmptyName),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(matches!(
            builder(dev).add(0, 8, SixteenByteName),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(builder(dev).add(0, 8, FifteenByteName).is_ok());
    }
}
