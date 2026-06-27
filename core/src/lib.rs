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

use std::path::Path;

/// Errors from opening or reading a ZIP entry.
#[derive(Debug, thiserror::Error)]
pub enum ZipCoreError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The underlying `zip` crate reported an error.
    #[error("zip error: {0}")]
    Zip(String),

    /// The entry's deflate stream was malformed (e.g. `LEN`/`NLEN` mismatch).
    #[error("malformed deflate stream in entry {entry}: {reason}")]
    Malformed {
        /// The entry whose stream is malformed.
        entry: String,
        /// What was wrong.
        reason: String,
    },
}

/// A random-access view over one uncompressed ZIP entry.
pub struct StoredZipEntry {
    #[allow(dead_code)]
    file: std::fs::File,
    uncompressed_size: u64,
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

    /// Read up to `buf.len()` bytes of the **uncompressed** entry starting at
    /// `offset`, without inflating from the start when the entry is stored-block
    /// addressable. Returns the number of bytes read (short at EOF).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        // STUB (RED): no block index yet — fill zeros.
        let _ = offset;
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(buf.len())
    }
}

/// Open a single entry of a ZIP archive for random access.
pub fn open_entry(path: &Path, name: &str) -> Result<StoredZipEntry, ZipCoreError> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path)?)
        .map_err(|e| ZipCoreError::Zip(e.to_string()))?;
    let entry = archive
        .by_name(name)
        .map_err(|e| ZipCoreError::Zip(e.to_string()))?;
    let uncompressed_size = entry.size();
    Ok(StoredZipEntry {
        file,
        uncompressed_size,
    })
}
