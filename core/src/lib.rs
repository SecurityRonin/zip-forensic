//! Forensic-grade ZIP reader.
//!
//! The headline capability is **deflate-block-indexed random access**: a forensic
//! image stored in a ZIP (an E01 `Defl:N` entry at ~0% compression) is, at the
//! deflate level, a run of *stored* blocks (`BTYPE=00`). Those blocks are
//! byte-aligned, so the uncompressed entry can be addressed at any offset by
//! seeking directly to the right block — **without inflating from the start**.
//! This lets a downstream reader (e.g. the EWF parser) random-access a multi-GB
//! image inside a ZIP with no temp extraction and no repeated decompression.
//!
//! Genuinely-compressed entries fall back to a correctness-preserving full
//! decompress (no worse than extracting the entry), so the type is universal.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod archive;
mod bytes;
mod codec;
mod cp437;

pub use archive::{CompressionMethod, ZipArchive, ZipFile};

use std::io::Read;
use std::path::{Path, PathBuf};

/// Errors from opening or reading a ZIP entry.
#[derive(Debug, thiserror::Error)]
pub enum ZipCoreError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The container structure was malformed.
    #[error("malformed ZIP container: {0}")]
    Format(#[from] FormatError),

    /// An entry uses a compression method this reader does not (yet) decode.
    #[error("unsupported compression method: {0:?}")]
    UnsupportedMethod(CompressionMethod),

    /// The decoded entry's CRC-32 did not match the central-directory value.
    #[error(
        "CRC-32 mismatch in entry {entry}: expected {expected:#010x}, computed {actual:#010x}"
    )]
    CrcMismatch {
        /// The entry whose CRC failed.
        entry: String,
        /// The CRC recorded in the central directory.
        expected: u32,
        /// The CRC computed over the decoded bytes.
        actual: u32,
    },

    /// No entry with the requested name exists.
    #[error("entry not found: {0}")]
    EntryNotFound(String),

    /// The requested entry index is out of range.
    #[error("entry index out of bounds: {0}")]
    IndexOutOfBounds(usize),

    /// The entry's deflate stream was malformed (e.g. `LEN`/`NLEN` mismatch).
    #[error("malformed deflate stream in entry {entry}: {reason}")]
    Malformed {
        /// The entry whose stream is malformed.
        entry: String,
        /// What was wrong.
        reason: String,
    },
}

/// Structural defects in a ZIP container. Each variant preserves the offending
/// value/location (CLAUDE.md "Show the unrecognized value").
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    /// A header read ran past the available bytes.
    #[error("unexpected end of data")]
    Truncated,

    /// No End Of Central Directory record was found.
    #[error("End Of Central Directory record not found")]
    NoEocd,

    /// A record did not start with its expected signature.
    #[error("bad signature for {what} at offset {offset}")]
    BadSignature {
        /// Which record was expected.
        what: &'static str,
        /// Where it was looked for.
        offset: u64,
    },

    /// The archive uses Zip64 features not yet implemented.
    #[error("Zip64 archive not yet supported")]
    Zip64Unsupported,

    /// The central directory offset/size fall outside the file.
    #[error("central directory out of range: offset {cd_offset}, size {cd_size}")]
    CentralDirOutOfRange {
        /// Declared central-directory offset.
        cd_offset: u64,
        /// Declared central-directory size.
        cd_size: u64,
    },

    /// The EOCD declared an entry count beyond the safety ceiling.
    #[error("declared entry count {0} exceeds the safety ceiling")]
    TooManyEntries(usize),
}

/// One byte-addressable stored (`BTYPE=00`) deflate block within an entry.
#[derive(Debug, Clone, Copy)]
struct StoredBlock {
    /// Offset of this block's first byte in the *uncompressed* entry.
    uncomp_start: u64,
    /// Number of raw bytes in the block (deflate `LEN`, ≤ 65535).
    len: u64,
    /// Offset in the *backing file* where this block's raw bytes begin.
    file_offset: u64,
}

/// How an entry is addressed for random access.
enum Layout {
    /// The deflate stream is entirely stored blocks — direct seek, no inflation.
    StoredBlocks(Vec<StoredBlock>),
    /// A genuinely-compressed entry: correctness-preserving full-decompress path.
    Fallback { path: PathBuf, name: String },
}

/// A random-access view over one uncompressed ZIP entry.
pub struct StoredZipEntry {
    file: std::fs::File,
    uncompressed_size: u64,
    layout: Layout,
}

impl StoredZipEntry {
    /// The uncompressed length of the entry, in bytes.
    pub fn len(&self) -> u64 {
        self.uncompressed_size
    }

    /// Whether the entry is empty.
    pub fn is_empty(&self) -> bool {
        self.uncompressed_size == 0
    }

    /// `true` when the entry is stored-block addressable (the fast, no-inflation
    /// path). `false` means reads go through the full-decompress fallback.
    pub fn is_stored_block_indexed(&self) -> bool {
        matches!(self.layout, Layout::StoredBlocks(_))
    }

    /// Read up to `buf.len()` bytes of the **uncompressed** entry starting at
    /// `offset`. Stored-block entries seek directly to the right block(s) with no
    /// inflation; this method takes `&self`, so independent reads run lock-free in
    /// parallel (positioned reads). Returns the number of bytes read (short at EOF).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        if offset >= self.uncompressed_size || buf.is_empty() {
            return Ok(0);
        }
        let want_end = (offset + buf.len() as u64).min(self.uncompressed_size);
        let total = (want_end - offset) as usize;
        match &self.layout {
            Layout::StoredBlocks(blocks) => {
                let mut filled = 0usize;
                let mut cur = offset;
                while cur < want_end {
                    // First block whose uncompressed span extends past `cur`.
                    let bi = blocks.partition_point(|b| b.uncomp_start + b.len <= cur);
                    let Some(b) = blocks.get(bi) else {
                        break; // cov:unreachable: blocks cover [0, uncompressed_size)
                    };
                    let within = cur - b.uncomp_start;
                    let avail = b.len - within;
                    let n = avail.min(want_end - cur) as usize;
                    pread_exact(
                        &self.file,
                        &mut buf[filled..filled + n],
                        b.file_offset + within,
                    )?;
                    filled += n;
                    cur += n as u64;
                }
                Ok(filled)
            }
            Layout::Fallback { path, name } => {
                // Rare path (genuinely-compressed entry): never hit by 0%-deflate
                // forensic images. Correct, if O(n) per read. Decoded by the native
                // pure-Rust parser (no zip-rs), CRC-verified on EOF.
                let mut archive =
                    ZipArchive::new(std::fs::File::open(path)?).map_err(std::io::Error::other)?;
                let mut entry = archive.by_name(name).map_err(std::io::Error::other)?;
                let mut all = Vec::with_capacity(self.uncompressed_size as usize);
                entry.read_to_end(&mut all)?;
                let start = offset as usize;
                let end = (start + total).min(all.len());
                let slice = &all[start..end];
                buf[..slice.len()].copy_from_slice(slice);
                Ok(slice.len())
            }
        }
    }
}

/// Open a single entry of a ZIP archive for random access.
pub fn open_entry(path: &Path, name: &str) -> Result<StoredZipEntry, ZipCoreError> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(std::fs::File::open(path)?)?;
    let entry = archive.by_name(name)?;
    let uncompressed_size = entry.size();
    let compressed_size = entry.compressed_size();
    let data_start = entry.data_start();
    let is_deflate = entry.compression() == CompressionMethod::Deflated;
    let is_stored = entry.compression() == CompressionMethod::Stored;
    drop(entry);
    drop(archive);

    let layout = if is_stored {
        // A method-0 entry is one contiguous run of raw bytes.
        Layout::StoredBlocks(vec![StoredBlock {
            uncomp_start: 0,
            len: uncompressed_size,
            file_offset: data_start,
        }])
    } else if is_deflate {
        match index_stored_blocks(&file, name, data_start, compressed_size, uncompressed_size)? {
            Some(blocks) => Layout::StoredBlocks(blocks),
            None => Layout::Fallback {
                path: path.to_path_buf(),
                name: name.to_string(),
            },
        }
    } else {
        Layout::Fallback {
            path: path.to_path_buf(),
            name: name.to_string(),
        }
    };

    Ok(StoredZipEntry {
        file,
        uncompressed_size,
        layout,
    })
}

/// Walk a deflate stream's block headers. Returns `Some(index)` when every block
/// is stored (`BTYPE=00`) — the byte-addressable fast path — or `None` the moment
/// a Huffman block appears (alignment is lost; caller uses the fallback).
fn index_stored_blocks(
    file: &std::fs::File,
    name: &str,
    data_start: u64,
    compressed_size: u64,
    uncompressed_size: u64,
) -> Result<Option<Vec<StoredBlock>>, ZipCoreError> {
    let end = data_start + compressed_size;
    let mut blocks = Vec::new();
    let mut foff = data_start;
    let mut uoff = 0u64;
    loop {
        if foff + 5 > end {
            // Ran out of stream before a final block — not a clean stored run.
            return Ok(None);
        }
        let mut hdr = [0u8; 5];
        pread_exact(file, &mut hdr, foff)?;
        let bfinal = hdr[0] & 1;
        let btype = (hdr[0] >> 1) & 0b11;
        if btype != 0 {
            return Ok(None); // a compressed block → not byte-addressable
        }
        let len = u16::from_le_bytes([hdr[1], hdr[2]]);
        let nlen = u16::from_le_bytes([hdr[3], hdr[4]]);
        if nlen != !len {
            return Err(ZipCoreError::Malformed {
                entry: name.to_string(),
                reason: format!("stored block LEN/NLEN mismatch at file offset {foff}"),
            });
        }
        let len = u64::from(len);
        let data_off = foff + 5;
        if data_off + len > end {
            return Err(ZipCoreError::Malformed {
                entry: name.to_string(),
                reason: format!("stored block overruns compressed data at offset {data_off}"),
            });
        }
        blocks.push(StoredBlock {
            uncomp_start: uoff,
            len,
            file_offset: data_off,
        });
        uoff += len;
        foff = data_off + len;
        if bfinal == 1 {
            break;
        }
    }
    if uoff != uncompressed_size {
        return Err(ZipCoreError::Malformed {
            entry: name.to_string(),
            reason: format!(
                "stored-block total {uoff} != entry uncompressed size {uncompressed_size}"
            ),
        });
    }
    Ok(Some(blocks))
}

#[cfg(unix)]
fn pread_exact(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn pread_exact(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut read = 0usize;
    while read < buf.len() {
        let n = file.seek_read(&mut buf[read..], offset + read as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short positioned read",
            ));
        }
        read += n;
    }
    Ok(())
}
