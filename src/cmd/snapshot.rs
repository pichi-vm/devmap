// SPDX-License-Identifier: Apache-2.0

//! Application workflows for persistent snapshot COW images.

use crate::cli::{SnapshotCmd, SnapshotConvert};
use anyhow::{Context as _, Result, bail};
use devmap_snapshot::{
    Layer,
    traits::std::{Create as _, Geometry as _, SyncData as _},
};
use devmap_zero::Zero;
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write};

pub(crate) fn run(cmd: SnapshotCmd) -> Result<()> {
    match cmd {
        SnapshotCmd::Convert(arguments) => convert(&arguments),
    }
}

fn convert(arguments: &SnapshotConvert) -> Result<()> {
    let formatter =
        devmap_snapshot::Formatter::new(arguments.chunk_size).context("set chunk size")?;
    let mut input =
        File::open(&arguments.raw).with_context(|| format!("open {}", arguments.raw.display()))?;
    let mut output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&arguments.cow)
        .with_context(|| format!("open {}", arguments.cow.display()))?;
    let input_meta = input.metadata().context("inspect input")?;
    let output_meta = output.metadata().context("inspect output")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        if (input_meta.dev() == output_meta.dev() && input_meta.ino() == output_meta.ino())
            || (input_meta.file_type().is_block_device()
                && output_meta.file_type().is_block_device()
                && input_meta.rdev() == output_meta.rdev())
        {
            bail!("input and COW storage alias");
        }
    }
    let input_bytes = input.byte_size().context("size input")?;
    let required = formatter
        .required_size(input_bytes, output.block_size().context("COW block size")?)
        .context("calculate COW capacity")?;
    if output_meta.is_file() {
        output.set_len(required).context("size COW file")?;
    } else if output.byte_size().context("size COW device")? < required {
        bail!("COW device is too small");
    }
    let mut layer = Layer::create(Zero::new(input_bytes), &mut output, arguments.chunk_size)
        .context("format snapshot")?;
    copy_sparse(&mut input, &mut layer, input_bytes).with_context(|| {
        format!(
            "copy {} into {}",
            arguments.raw.display(),
            arguments.cow.display()
        )
    })?;
    layer.sync_data().context("persist snapshot")?;
    drop(layer);
    println!(
        "Converted {} -> {}",
        arguments.raw.display(),
        arguments.cow.display()
    );
    println!("  Chunk size:      {} sectors", arguments.chunk_size);
    let chunk_bytes = u64::from(arguments.chunk_size.get()) * 512;
    println!("  Input chunks:    {}", input_bytes.div_ceil(chunk_bytes));
    println!("  COW size:        {} bytes", output.byte_size()?);
    Ok(())
}

// The caller supplies a zero-backed output: skipped holes must already read as
// zero. Filesystems without extent queries fall back to copying every byte.
fn copy_sparse(
    input: &mut File,
    output: &mut (impl Write + io::Seek),
    length: u64,
) -> io::Result<()> {
    let mut position = 0;
    #[cfg(target_os = "linux")]
    let mut seek_extents = true;
    while position < length {
        #[cfg(target_os = "linux")]
        let (start, end) = if seek_extents {
            let start = match rustix::fs::seek(&*input, rustix::fs::SeekFrom::Data(position)) {
                Ok(start) => start.min(length),
                Err(rustix::io::Errno::NXIO) => break,
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOTSUP) => {
                    seek_extents = false;
                    position
                }
                Err(error) => return Err(io::Error::from(error)),
            };
            if start == length {
                break;
            }
            let end = if seek_extents {
                match rustix::fs::seek(&*input, rustix::fs::SeekFrom::Hole(start)) {
                    Ok(end) => end.min(length),
                    Err(
                        rustix::io::Errno::NXIO
                        | rustix::io::Errno::INVAL
                        | rustix::io::Errno::NOTSUP,
                    ) => length,
                    Err(error) => return Err(io::Error::from(error)),
                }
            } else {
                length
            };
            (start, end)
        } else {
            (position, length)
        };
        #[cfg(not(target_os = "linux"))]
        let (start, end) = (position, length);
        if end <= start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse extent does not advance",
            ));
        }
        input.seek(SeekFrom::Start(start))?;
        output.seek(SeekFrom::Start(start))?;
        let count = end - start;
        if io::copy(&mut io::Read::by_ref(input).take(count), output)? != count {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        position = end;
    }
    output.seek(SeekFrom::Start(length))?;
    Ok(())
}
