// SPDX-License-Identifier: Apache-2.0

//! The dm-snapshot **persistent COW** (exception store) on-disk format.
//! Byte-exact per `drivers/md/dm-snap-persistent.c` — a pure-Rust way to
//! turn a raw image into a snapshot COW with no external tool.
//!
//! All multi-byte fields are little-endian (`__le32` / `__le64`). All
//! `chunk` indices are *chunk* indices (chunk = `chunk_size_sectors *
//! SECTOR_SIZE` bytes), NOT sector indices.
//!
//! # Model
//!
//! [`CowWriter`] is the engine: a `Seek + Write` COW sink presented as the
//! origin image's chunk address space. You [`push`](CowWriter::push) whole
//! chunks by index — the first write of a chunk allocates a data slot and
//! appends its `(old → new)` exception; a later write of the same index
//! overwrites that slot in place (faithful to how the kernel handles a
//! repeat write). An all-zero chunk that was never written is simply left
//! out, so the COW layers sparsely over a zero origin. [`done`] finalises.
//!
//! [`convert`] and [`convert_sparse`] are thin drivers over it (sequential
//! and hole-skipping); [`write`] is an in-memory convenience.
//!
//! # Layout
//!
//! ```text
//! chunk 0:                                 header (disk_header, zero-padded)
//! chunk 1:                                 metadata area 0 (exceptions_per_area entries)
//! chunks 2 .. 2 + exceptions_per_area - 1: data area 0
//! chunk (1 + exc_per_area + 1):            metadata area 1
//! ...
//! ```
//!
//! where `exceptions_per_area = chunk_bytes / 16`. The allocator walks
//! `next_free` forward one chunk per exception and skips metadata-chunk
//! slots ([`bump_past_metadata`]). The end of the exceptions is a
//! `disk_exception` with `new_chunk == 0` (invalid, since chunk 0 is the
//! header).
//!
//! # History
//!
//! Lifted from pichi's `pichi-import` crate, where kernel acceptance was
//! deferred to a self round-trip test. Here it is a first-class format
//! crate: typed errors, a public reader, and a real kernel cross-check
//! (see `tests/end_to_end.rs`).
//!
//! [`done`]: CowWriter::done

// Chunk/byte offsets are u64 on the wire but index in-memory buffers whose
// size is bounded by the COW length; on any target that can address the COW
// the u64->usize casts can't truncate. The module docs also reference kernel
// source files (dm-snap-persistent.c) that read fine unquoted.
#![allow(clippy::cast_possible_truncation, clippy::doc_markdown)]

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

/// "SnAp" little-endian — `dm-snap-persistent.c` `SNAP_MAGIC`.
pub const SNAP_MAGIC: u32 = 0x7041_6e53;
/// `SNAPSHOT_DISK_VERSION`.
pub const SNAPSHOT_DISK_VERSION: u32 = 1;
/// `NUM_SNAPSHOT_HDR_CHUNKS` — the header occupies chunk 0 alone.
pub const NUM_SNAPSHOT_HDR_CHUNKS: u64 = 1;
/// 512 bytes per sector (kernel-wide).
pub const SECTOR_SIZE: u32 = 512;
/// `DM_CHUNK_SIZE_DEFAULT_SECTORS` = 32 sectors = 16 KiB.
pub const DEFAULT_CHUNK_SIZE_SECTORS: u32 = 32;
/// `sizeof(struct disk_exception)` — `__le64 old_chunk; __le64 new_chunk;`.
pub const DISK_EXCEPTION_SIZE: usize = 16;
/// The 16-byte disk header: four `__le32` — magic, valid, version, chunk_size.
const DISK_HEADER_SIZE: usize = 16;
/// dm requires a chunk size of at least 8 sectors.
///
/// The kernel's true floor is the logical block size of the origin and COW
/// devices (`chunk_size % (logical_block_size >> 9)` must be zero), which
/// is only knowable once those devices are named. 8 sectors is the
/// conservative choice: it satisfies a 4 KiB-logical device, the largest
/// block size in common use.
pub const MIN_CHUNK_SIZE_SECTORS: u32 = 8;

/// The largest chunk size dm accepts: `INT_MAX >> SECTOR_SHIFT`
/// (`dm_exception_store_set_chunk_size`, "Chunk size is too high").
///
/// Combined with the power-of-two rule this makes 2^21 sectors (1 GiB) the
/// largest usable chunk, since 2^22 exceeds this bound.
pub const MAX_CHUNK_SIZE_SECTORS: u32 = i32::MAX as u32 >> 9;

/// Why a chunk size is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChunkSizeError {
    /// The chunk size was zero.
    #[error("chunk size must be greater than zero")]
    Zero,

    /// The chunk size is not a power of two, which dm requires.
    #[error("chunk size must be a power of two (got {0} sectors)")]
    NotPowerOfTwo(u32),

    /// The chunk size is below the 8-sector kernel minimum.
    #[error("chunk size must be at least {MIN_CHUNK_SIZE_SECTORS} sectors (got {0})")]
    TooSmall(u32),

    /// The chunk size exceeds what dm accepts (`INT_MAX >> SECTOR_SHIFT`).
    #[error("chunk size must be at most {MAX_CHUNK_SIZE_SECTORS} sectors (got {0})")]
    TooLarge(u32),
}

/// Why writing a COW failed.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The requested chunk size is invalid.
    // Transparent: `#[from]` already exposes the inner error as `source()`,
    // so a wrapping prefix here would print the same sentence twice in a
    // chain-formatted report.
    #[error(transparent)]
    ChunkSize(#[from] ChunkSizeError),

    /// A chunk handed to [`CowWriter::push`] was not exactly one chunk long.
    #[error("chunk must be exactly {expected} bytes, got {got}")]
    ChunkLen {
        /// The chunk size in bytes.
        expected: usize,
        /// The length actually supplied.
        got: usize,
    },

    /// An I/O error reading the input or writing the COW.
    #[error("cow I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Why a COW blob failed to parse.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The blob is smaller than the 16-byte header.
    #[error("cow too small for header")]
    TooSmall,

    /// The `SnAp` magic is absent.
    #[error("bad magic: 0x{0:08x} (expected 0x{SNAP_MAGIC:08x})")]
    BadMagic(u32),

    /// The header's `valid` flag is not 1.
    #[error("snapshot marked invalid (valid = {0})")]
    NotValid(u32),

    /// The on-disk version is not [`SNAPSHOT_DISK_VERSION`].
    #[error("unsupported disk version: {0} (expected {SNAPSHOT_DISK_VERSION})")]
    BadVersion(u32),

    /// The header records an unusable chunk size.
    #[error(transparent)]
    ChunkSize(#[from] ChunkSizeError),
}

/// Validate a chunk size in 512-byte sectors against dm's rules: non-zero,
/// a power of two, and within
/// [`MIN_CHUNK_SIZE_SECTORS`]..=[`MAX_CHUNK_SIZE_SECTORS`].
///
/// Catching these here means a bad `--chunk-size` fails before any bytes
/// are written, rather than at table load. The one rule that cannot be
/// checked without the devices — that the chunk size is a multiple of the
/// origin's and COW's logical block size — the kernel enforces on
/// activation; [`MIN_CHUNK_SIZE_SECTORS`] covers the common case.
///
/// # Errors
///
/// A [`ChunkSizeError`] describing the first constraint the value violates.
pub fn validate_chunk_size(sectors: u32) -> Result<(), ChunkSizeError> {
    if sectors == 0 {
        return Err(ChunkSizeError::Zero);
    }
    if !sectors.is_power_of_two() {
        return Err(ChunkSizeError::NotPowerOfTwo(sectors));
    }
    if sectors < MIN_CHUNK_SIZE_SECTORS {
        return Err(ChunkSizeError::TooSmall(sectors));
    }
    if sectors > MAX_CHUNK_SIZE_SECTORS {
        return Err(ChunkSizeError::TooLarge(sectors));
    }
    Ok(())
}

/// What [`CowWriter::done`] produced.
#[derive(Debug, Clone, Copy)]
pub struct CowStreamMeta {
    /// Total length of the COW in bytes (`total_chunks * chunk_bytes`); the
    /// sink is extended to this length before `done` returns.
    pub total_bytes: u64,
    /// Number of exceptions written (one per distinct non-zero chunk).
    pub exception_count: u64,
    /// Chunk size in 512-byte sectors, echoed from the caller.
    pub chunk_size_sectors: u32,
}

/// Encode the 16-byte disk header for `chunk_size_sectors`.
fn header_bytes(chunk_size_sectors: u32) -> [u8; DISK_HEADER_SIZE] {
    let mut h = [0u8; DISK_HEADER_SIZE];
    h[0..4].copy_from_slice(&SNAP_MAGIC.to_le_bytes());
    h[4..8].copy_from_slice(&1u32.to_le_bytes()); // valid = 1
    h[8..12].copy_from_slice(&SNAPSHOT_DISK_VERSION.to_le_bytes());
    h[12..16].copy_from_slice(&chunk_size_sectors.to_le_bytes());
    h
}

/// Encode one `disk_exception` entry.
fn exception_bytes(old_chunk: u64, new_chunk: u64) -> [u8; DISK_EXCEPTION_SIZE] {
    let mut e = [0u8; DISK_EXCEPTION_SIZE];
    e[0..8].copy_from_slice(&old_chunk.to_le_bytes());
    e[8..16].copy_from_slice(&new_chunk.to_le_bytes());
    e
}

/// `dm-snap-persistent.c` `skip_metadata`. Returns `next_free` bumped by
/// one if it would land on a metadata-chunk slot, else unchanged.
///
/// Metadata chunks live at `NUM_SNAPSHOT_HDR_CHUNKS + N * area_stride_chunks`.
///
/// # Panics
///
/// If `next_free < NUM_SNAPSHOT_HDR_CHUNKS`. [`CowWriter`] initialises
/// `next_free = NUM_SNAPSHOT_HDR_CHUNKS` and only increments, so this holds
/// in practice; a violation would silently write data into a metadata chunk.
#[must_use]
pub fn bump_past_metadata(next_free: u64, area_stride_chunks: u64) -> u64 {
    assert!(
        next_free >= NUM_SNAPSHOT_HDR_CHUNKS,
        "bump_past_metadata: next_free ({next_free}) must be >= {NUM_SNAPSHOT_HDR_CHUNKS}"
    );
    if (next_free - NUM_SNAPSHOT_HDR_CHUNKS).is_multiple_of(area_stride_chunks) {
        next_free + 1
    } else {
        next_free
    }
}

/// A dm-snapshot persistent COW writer: a `Seek + Write` sink `W` presented
/// as the origin image's chunk address space.
///
/// Feed whole chunks with [`push`](Self::push) (index = origin chunk), then
/// call [`done`](Self::done). The first `push` of an index allocates a COW
/// data chunk and appends its exception; a repeat `push` of the same index
/// overwrites that data in place. An index never pushed (or pushed all-zero
/// on first touch) has no exception and reads back from the zero origin.
#[derive(Debug)]
pub struct CowWriter<W: Write + Seek> {
    inner: W,
    chunk_bytes: usize,
    exceptions_per_area: usize,
    area_stride_chunks: u64,
    chunk_size_sectors: u32,
    /// Next unallocated COW chunk (bumped past metadata slots on use).
    next_free: u64,
    /// Exceptions appended so far — indexes the metadata slot for the next.
    exception_count: u64,
    /// Highest COW data chunk allocated, for sizing in `done`.
    max_new_chunk: u64,
    /// origin chunk → allocated COW data chunk, for in-place rewrites.
    allocated: BTreeMap<u64, u64>,
}

impl<W: Write + Seek> CowWriter<W> {
    /// Start a COW over `inner`, writing the header at offset 0.
    ///
    /// # Errors
    ///
    /// [`WriteError::ChunkSize`] for an invalid chunk size, or
    /// [`WriteError::Io`] if the header write fails.
    pub fn new(mut inner: W, chunk_size_sectors: u32) -> Result<Self, WriteError> {
        validate_chunk_size(chunk_size_sectors)?;
        let chunk_bytes = chunk_size_sectors as usize * SECTOR_SIZE as usize;
        let exceptions_per_area = chunk_bytes / DISK_EXCEPTION_SIZE;
        inner.seek(SeekFrom::Start(0))?;
        inner.write_all(&header_bytes(chunk_size_sectors))?;
        Ok(Self {
            inner,
            chunk_bytes,
            exceptions_per_area,
            area_stride_chunks: (exceptions_per_area + 1) as u64,
            chunk_size_sectors,
            next_free: NUM_SNAPSHOT_HDR_CHUNKS,
            exception_count: 0,
            max_new_chunk: 0,
            allocated: BTreeMap::new(),
        })
    }

    /// The chunk size in bytes — what every [`push`](Self::push) chunk must be.
    #[must_use]
    pub fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    /// Write origin chunk `index` (its data becomes a COW exception).
    ///
    /// `chunk.len()` MUST equal [`chunk_bytes`](Self::chunk_bytes); a short
    /// final chunk is the caller's job to zero-pad. The first push of an
    /// `index` allocates a data slot and appends its exception; a repeat
    /// push overwrites that slot in place. An all-zero chunk whose `index`
    /// has not been allocated is dropped (it reads from the zero origin).
    ///
    /// # Errors
    ///
    /// [`WriteError::ChunkLen`] if `chunk` is the wrong length, or
    /// [`WriteError::Io`] on a write failure.
    pub fn push(&mut self, index: u64, chunk: &[u8]) -> Result<(), WriteError> {
        if chunk.len() != self.chunk_bytes {
            return Err(WriteError::ChunkLen {
                expected: self.chunk_bytes,
                got: chunk.len(),
            });
        }

        // Rewrite of an already-allocated chunk: overwrite its data in place,
        // no new exception (matches the kernel's repeat-write behaviour).
        if let Some(&new_chunk) = self.allocated.get(&index) {
            self.write_data(new_chunk, chunk)?;
            return Ok(());
        }

        // First touch of an all-zero chunk: no exception; the zero origin
        // serves it.
        if chunk.iter().all(|&b| b == 0) {
            return Ok(());
        }

        // Allocate a data chunk, skipping any metadata-chunk slot.
        self.next_free = bump_past_metadata(self.next_free, self.area_stride_chunks);
        let new_chunk = self.next_free;
        self.next_free += 1;
        self.max_new_chunk = self.max_new_chunk.max(new_chunk);

        // Append the exception entry into its metadata-area slot.
        let slot = self.exception_count as usize % self.exceptions_per_area;
        let area = self.exception_count / self.exceptions_per_area as u64;
        let metadata_chunk = NUM_SNAPSHOT_HDR_CHUNKS + area * self.area_stride_chunks;
        let entry_off =
            metadata_chunk * self.chunk_bytes as u64 + (slot * DISK_EXCEPTION_SIZE) as u64;
        self.inner.seek(SeekFrom::Start(entry_off))?;
        self.inner.write_all(&exception_bytes(index, new_chunk))?;

        self.write_data(new_chunk, chunk)?;
        self.allocated.insert(index, new_chunk);
        self.exception_count += 1;
        Ok(())
    }

    /// Write a chunk's data into its COW data slot.
    fn write_data(&mut self, new_chunk: u64, chunk: &[u8]) -> Result<(), std::io::Error> {
        self.inner
            .seek(SeekFrom::Start(new_chunk * self.chunk_bytes as u64))?;
        self.inner.write_all(chunk)
    }

    /// Finalise: ensure the trailing sentinel metadata chunk is present and
    /// the sink is exactly the COW length, then flush. Returns the COW size
    /// and exception count.
    ///
    /// # Errors
    ///
    /// [`WriteError::Io`] if the final extend or flush fails.
    pub fn done(mut self) -> Result<CowStreamMeta, WriteError> {
        let mut total_chunks = self.max_new_chunk.max(NUM_SNAPSHOT_HDR_CHUNKS) + 1;
        // If the last metadata area filled exactly, the reader needs the
        // next area's (zero) metadata chunk present as the sentinel.
        if self.exception_count > 0
            && self
                .exception_count
                .is_multiple_of(self.exceptions_per_area as u64)
        {
            let n_areas = self.exception_count / self.exceptions_per_area as u64;
            let next_area_metadata = NUM_SNAPSHOT_HDR_CHUNKS + n_areas * self.area_stride_chunks;
            total_chunks = total_chunks.max(next_area_metadata + 1);
        }
        total_chunks = total_chunks.max(2);
        let total_bytes = total_chunks * self.chunk_bytes as u64;

        // Extend to the exact length only if shorter — sparse metadata
        // chunks and trailing holes read back as the zero sentinel.
        let cur_end = self.inner.seek(SeekFrom::End(0))?;
        if cur_end < total_bytes {
            self.inner.seek(SeekFrom::Start(total_bytes - 1))?;
            self.inner.write_all(&[0u8])?;
        }
        self.inner.flush()?;

        Ok(CowStreamMeta {
            total_bytes,
            exception_count: self.exception_count,
            chunk_size_sectors: self.chunk_size_sectors,
        })
    }
}

/// Convert a raw image read sequentially from `input` into a persistent COW
/// on `output`. All-zero chunks are elided (they layer over a zero origin).
///
/// # Errors
///
/// [`WriteError`] on an invalid chunk size or any I/O error.
pub fn convert<R: Read, W: Write + Seek>(
    input: &mut R,
    output: W,
    chunk_size_sectors: u32,
) -> Result<CowStreamMeta, WriteError> {
    let mut cow = CowWriter::new(output, chunk_size_sectors)?;
    let mut buf = vec![0u8; cow.chunk_bytes()];
    let mut index = 0u64;
    loop {
        buf.fill(0);
        let filled = read_full(input, &mut buf)?;
        if filled == 0 {
            break;
        }
        // A short final read is already zero-padded to a full chunk in `buf`.
        cow.push(index, &buf)?;
        index += 1;
        if filled < buf.len() {
            break;
        }
    }
    cow.done()
}

/// Sparse-aware [`convert`] for a real file: uses `SEEK_DATA` / `SEEK_HOLE`
/// to skip whole chunks inside a hole without reading them. Output is
/// byte-identical to [`convert`] over the same logical content.
///
/// # Errors
///
/// [`WriteError`] on an invalid chunk size or any I/O error.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn convert_sparse<W: Write + Seek>(
    input: &std::fs::File,
    input_len: u64,
    output: W,
    chunk_size_sectors: u32,
) -> Result<CowStreamMeta, WriteError> {
    use std::os::unix::fs::FileExt as _;

    let mut cow = CowWriter::new(output, chunk_size_sectors)?;
    let chunk_bytes = cow.chunk_bytes() as u64;
    let mut buf = vec![0u8; cow.chunk_bytes()];

    let mut pos = 0u64;
    let mut index = 0u64;
    let mut data_start = 0u64;
    let mut data_end = 0u64;
    while pos < input_len {
        // Re-probe the data extent once we've walked past the last one.
        if pos >= data_end {
            match rustix::fs::seek(input, rustix::fs::SeekFrom::Data(pos)) {
                Ok(d) => {
                    data_start = d;
                    data_end = rustix::fs::seek(input, rustix::fs::SeekFrom::Hole(d))
                        .map_err(std::io::Error::from)?;
                }
                // No data at/after `pos` — the rest of the file is a hole.
                Err(rustix::io::Errno::NXIO) => break,
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        let chunk_end = (pos + chunk_bytes).min(input_len);
        if chunk_end > data_start {
            // Overlaps real data: read it (hole bytes read as zeros) and push.
            buf.fill(0);
            let want = (chunk_end - pos) as usize;
            input.read_exact_at(&mut buf[..want], pos)?;
            cow.push(index, &buf)?;
        }
        // A chunk entirely before `data_start` is a hole — skip (no push).
        pos += chunk_bytes;
        index += 1;
    }
    cow.done()
}

/// Convert an in-memory raw image into a persistent COW blob. A convenience
/// over [`CowWriter`] for tests and small inputs.
///
/// # Errors
///
/// [`WriteError::ChunkSize`] if `chunk_size_sectors` is invalid.
pub fn write(input: &[u8], chunk_size_sectors: u32) -> Result<Vec<u8>, WriteError> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    convert(&mut &input[..], &mut cursor, chunk_size_sectors)?;
    Ok(cursor.into_inner())
}

/// Read up to `buf.len()` bytes, looping over short reads. Returns the
/// number of bytes filled.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// The parsed disk header of a persistent COW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Whether the snapshot is marked valid.
    pub valid: bool,
    /// The on-disk format version.
    pub version: u32,
    /// The chunk size in 512-byte sectors.
    pub chunk_size_sectors: u32,
}

impl Header {
    /// Parse and validate the 16-byte header at the start of a COW blob.
    ///
    /// # Errors
    ///
    /// [`ParseError`] if the blob is too short, the magic/version/valid
    /// fields are wrong, or the chunk size is unusable.
    // The length check guards every subsequent 4-byte read, so the
    // `try_into().unwrap()`s below cannot panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_bytes(cow: &[u8]) -> Result<Header, ParseError> {
        if cow.len() < DISK_HEADER_SIZE {
            return Err(ParseError::TooSmall);
        }
        let word = |o: usize| u32::from_le_bytes(cow[o..o + 4].try_into().unwrap());
        let magic = word(0);
        if magic != SNAP_MAGIC {
            return Err(ParseError::BadMagic(magic));
        }
        let valid = word(4);
        if valid != 1 {
            return Err(ParseError::NotValid(valid));
        }
        let version = word(8);
        if version != SNAPSHOT_DISK_VERSION {
            return Err(ParseError::BadVersion(version));
        }
        let chunk_size_sectors = word(12);
        validate_chunk_size(chunk_size_sectors)?;
        Ok(Header {
            valid: true,
            version,
            chunk_size_sectors,
        })
    }
}

/// The exception map recovered from a COW: origin chunk → COW data chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionMap {
    /// Chunk size in 512-byte sectors, from the header.
    pub chunk_size_sectors: u32,
    /// Map from `old_chunk` (origin) to `new_chunk` (COW data slot).
    pub exceptions: BTreeMap<u64, u64>,
}

impl ExceptionMap {
    /// Parse a COW blob's header and walk its metadata areas into an
    /// exception map, stopping at the `new_chunk == 0` sentinel.
    ///
    /// # Errors
    ///
    /// [`ParseError`] if the header is invalid.
    // `total_chunks` is derived from `cow.len()`, so every metadata-slot
    // read below stays in bounds and the `try_into().unwrap()`s can't panic.
    #[allow(clippy::missing_panics_doc)]
    pub fn from_cow(cow: &[u8]) -> Result<ExceptionMap, ParseError> {
        let header = Header::from_bytes(cow)?;
        let chunk_bytes = header.chunk_size_sectors as usize * SECTOR_SIZE as usize;
        let exceptions_per_area = chunk_bytes / DISK_EXCEPTION_SIZE;
        let area_stride_chunks = (exceptions_per_area + 1) as u64;
        let total_chunks = (cow.len() / chunk_bytes) as u64;

        let mut exceptions = BTreeMap::new();
        let mut area: u64 = 0;
        'areas: loop {
            let metadata_chunk = NUM_SNAPSHOT_HDR_CHUNKS + area * area_stride_chunks;
            if metadata_chunk >= total_chunks {
                break;
            }
            let metadata_off = metadata_chunk as usize * chunk_bytes;
            for slot in 0..exceptions_per_area {
                let entry_off = metadata_off + slot * DISK_EXCEPTION_SIZE;
                let old_chunk =
                    u64::from_le_bytes(cow[entry_off..entry_off + 8].try_into().unwrap());
                let new_chunk =
                    u64::from_le_bytes(cow[entry_off + 8..entry_off + 16].try_into().unwrap());
                if new_chunk == 0 {
                    break 'areas;
                }
                exceptions.insert(old_chunk, new_chunk);
            }
            area += 1;
        }

        Ok(ExceptionMap {
            chunk_size_sectors: header.chunk_size_sectors,
            exceptions,
        })
    }
}

/// Borrow the COW data chunk at `new_chunk` (as returned in an
/// [`ExceptionMap`]).
#[must_use]
pub fn chunk_data(cow: &[u8], chunk_size_sectors: u32, new_chunk: u64) -> &[u8] {
    let chunk_bytes = chunk_size_sectors as usize * SECTOR_SIZE as usize;
    let off = new_chunk as usize * chunk_bytes;
    &cow[off..off + chunk_bytes]
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn header_magic_le() {
        let chunk_bytes = 32 * SECTOR_SIZE as usize;
        let mut input = vec![0u8; chunk_bytes];
        input[0] = 0xFF;
        let cow = write(&input, 32).unwrap();
        assert_eq!(&cow[0..4], &[0x53, 0x6e, 0x41, 0x70]);
        assert_eq!(&cow[4..8], &1u32.to_le_bytes(), "valid = 1");
        assert_eq!(&cow[8..12], &1u32.to_le_bytes(), "version = 1");
        assert_eq!(&cow[12..16], &32u32.to_le_bytes(), "chunk_size in sectors");
    }

    #[test]
    fn single_nonzero_chunk_uses_new_chunk_two() {
        let chunk_bytes = 32 * SECTOR_SIZE as usize;
        let mut input = vec![0u8; 4 * chunk_bytes];
        input[2 * chunk_bytes] = 0x42;
        let cow = write(&input, 32).unwrap();
        let map = ExceptionMap::from_cow(&cow).unwrap();
        assert_eq!(map.exceptions.len(), 1);
        assert_eq!(map.exceptions[&2], 2, "chunk 0=hdr, 1=md, 2=first data");
    }

    #[test]
    fn skip_zero_chunks() {
        let chunk_bytes = 32 * SECTOR_SIZE as usize;
        let input = vec![0u8; 8 * chunk_bytes];
        let cow = write(&input, 32).unwrap();
        assert!(ExceptionMap::from_cow(&cow).unwrap().exceptions.is_empty());
    }

    #[test]
    fn push_rejects_wrong_chunk_length() {
        let mut cow = CowWriter::new(Cursor::new(Vec::new()), 8).unwrap();
        let err = cow.push(0, &[0u8; 100]).unwrap_err();
        assert!(matches!(err, WriteError::ChunkLen { .. }));
    }

    #[test]
    fn repush_overwrites_in_place_without_new_exception() {
        let css = 8u32;
        let cb = css as usize * SECTOR_SIZE as usize;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut cow = CowWriter::new(&mut cursor, css).unwrap();
            cow.push(0, &vec![0xAAu8; cb]).unwrap();
            // Rewrite the same origin chunk — must reuse its data slot.
            cow.push(0, &vec![0xBBu8; cb]).unwrap();
            let meta = cow.done().unwrap();
            assert_eq!(meta.exception_count, 1, "repeat push adds no exception");
        }
        let cow = cursor.into_inner();
        let map = ExceptionMap::from_cow(&cow).unwrap();
        assert_eq!(map.exceptions.len(), 1);
        let data = chunk_data(&cow, css, map.exceptions[&0]);
        assert!(data.iter().all(|&b| b == 0xBB), "last write wins");
    }

    #[test]
    fn out_of_order_pushes_round_trip() {
        let css = 8u32;
        let cb = css as usize * SECTOR_SIZE as usize;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut cow = CowWriter::new(&mut cursor, css).unwrap();
            // Descending indices — the exception map doesn't care about order.
            cow.push(9, &vec![0x99u8; cb]).unwrap();
            cow.push(4, &vec![0x44u8; cb]).unwrap();
            cow.done().unwrap();
        }
        let cow = cursor.into_inner();
        let map = ExceptionMap::from_cow(&cow).unwrap();
        assert_eq!(map.exceptions.len(), 2);
        assert!(
            chunk_data(&cow, css, map.exceptions[&9])
                .iter()
                .all(|&b| b == 0x99)
        );
        assert!(
            chunk_data(&cow, css, map.exceptions[&4])
                .iter()
                .all(|&b| b == 0x44)
        );
    }

    #[test]
    fn area_filled_exactly_writes_next_zero_metadata() {
        let css = 8u32;
        let chunk_bytes = css as usize * SECTOR_SIZE as usize;
        let exceptions_per_area = chunk_bytes / DISK_EXCEPTION_SIZE; // 256
        let mut input = vec![0u8; exceptions_per_area * chunk_bytes];
        for i in 0..exceptions_per_area {
            input[i * chunk_bytes] = (i % 251) as u8 + 1;
        }
        let cow = write(&input, css).unwrap();
        let map = ExceptionMap::from_cow(&cow).unwrap();
        assert_eq!(map.exceptions.len(), exceptions_per_area);

        let area_stride = (exceptions_per_area + 1) as u64;
        let next_area_md = NUM_SNAPSHOT_HDR_CHUNKS + area_stride;
        let off = next_area_md as usize * chunk_bytes;
        assert!(cow.len() >= off + chunk_bytes, "next-area metadata present");
        assert!(
            cow[off..off + chunk_bytes].iter().all(|&b| b == 0),
            "next-area metadata is a zero sentinel"
        );
    }

    #[test]
    fn round_trip_byte_exact() {
        let css = 32u32;
        let chunk_bytes = css as usize * SECTOR_SIZE as usize;
        let mut input = vec![0u8; 100 * chunk_bytes];
        let nonzero: &[(usize, u8)] = &[(5, 0xA1), (17, 0xB2), (42, 0xC3), (99, 0xD4)];
        for &(idx, fill) in nonzero {
            input[idx * chunk_bytes..(idx + 1) * chunk_bytes].fill(fill);
        }

        let cow = write(&input, css).unwrap();
        let map = ExceptionMap::from_cow(&cow).unwrap();
        assert_eq!(map.exceptions.len(), nonzero.len());
        for &(src_idx, fill) in nonzero {
            let new_chunk = map.exceptions[&(src_idx as u64)];
            let recovered = chunk_data(&cow, map.chunk_size_sectors, new_chunk);
            assert!(recovered.iter().all(|&b| b == fill), "chunk {src_idx}");
        }
        for src_idx in 0..100 {
            if !nonzero.iter().any(|(i, _)| *i == src_idx) {
                assert!(!map.exceptions.contains_key(&(src_idx as u64)));
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn sparse_matches_sequential() {
        use std::os::unix::fs::FileExt as _;
        let css = 8u32;
        let cb = css as usize * SECTOR_SIZE as usize;
        let n_chunks = 64usize;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.img");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.set_len((n_chunks * cb) as u64).unwrap();
        f.write_all_at(&vec![0xEEu8; cb], (3 * cb) as u64).unwrap();
        f.write_all_at(&vec![0x77u8; cb], (50 * cb) as u64).unwrap();
        f.sync_all().unwrap();
        let len = f.metadata().unwrap().len();

        let mut sparse_out = Cursor::new(Vec::new());
        let sparse_meta = convert_sparse(&f, len, &mut sparse_out, css).unwrap();

        let mut seq_in = std::fs::File::open(&path).unwrap();
        let mut seq_out = Cursor::new(Vec::new());
        let seq_meta = convert(&mut seq_in, &mut seq_out, css).unwrap();

        assert_eq!(sparse_out.into_inner(), seq_out.into_inner());
        assert_eq!(sparse_meta.exception_count, 2);
        assert_eq!(sparse_meta.total_bytes, seq_meta.total_bytes);
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut cow = write(&[0xFFu8; 32 * SECTOR_SIZE as usize], 32).unwrap();
        cow[0] ^= 0xFF;
        assert!(matches!(
            ExceptionMap::from_cow(&cow),
            Err(ParseError::BadMagic(_))
        ));
    }

    #[test]
    fn validate_chunk_size_rejects_bad_values() {
        assert_eq!(validate_chunk_size(0), Err(ChunkSizeError::Zero));
        assert_eq!(
            validate_chunk_size(9),
            Err(ChunkSizeError::NotPowerOfTwo(9))
        );
        assert_eq!(validate_chunk_size(4), Err(ChunkSizeError::TooSmall(4)));
        assert!(validate_chunk_size(8).is_ok());
        assert!(validate_chunk_size(32).is_ok());
    }

    #[test]
    fn validate_chunk_size_enforces_the_kernel_upper_bound() {
        // INT_MAX >> SECTOR_SHIFT. With the power-of-two rule that makes
        // 2^21 sectors (1 GiB) the largest usable chunk; 2^22 is over it.
        assert_eq!(MAX_CHUNK_SIZE_SECTORS, 4_194_303);
        assert!(validate_chunk_size(1 << 21).is_ok(), "2^21 sectors = 1 GiB");
        assert_eq!(
            validate_chunk_size(1 << 22),
            Err(ChunkSizeError::TooLarge(1 << 22))
        );
    }
}
