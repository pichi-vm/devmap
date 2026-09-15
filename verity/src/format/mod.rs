// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "tokio")]
mod r#async;
mod sync;

impl crate::Parameters {
    fn validate_format_geometry(
        &self,
        data_block: std::num::NonZeroU32,
        hash_block: std::num::NonZeroU32,
    ) -> std::io::Result<()> {
        if self.data_block_size().get() % data_block.get() != 0
            || self.hash_block_size().get() % hash_block.get() != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "verity block sizes are incompatible with endpoint geometry",
            ));
        }
        Ok(())
    }
}
