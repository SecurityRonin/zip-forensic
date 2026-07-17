//! Block-indexed random access (seek) for Deflate64 (method 9).
//!
//! Genuinely-compressed Deflate64 is not byte-addressable the way a run of
//! stored blocks is, so seeking uses the `deflate64` crate's **checkpoint**
//! feature: the member is decoded once at open to capture decoder checkpoints at
//! fixed decompressed-output intervals. A [`read_at`](Deflate64Index::read_at)
//! restores the nearest checkpoint at or before the target offset, seeks the
//! compressed input there, and skips forward — re-inflating at most one interval
//! of output to reach any offset instead of decoding from the start.
//!
//! This mirrors the stored-block fast path used for method 0 / method 8: a
//! zero-copy stored run is still preferred (see `index_stored_blocks`); this path
//! covers the compressed case that stored-block indexing cannot address.

use std::fs::File;
use std::io;

use deflate64::InflaterManaged;

use crate::{pread_exact, ZipCoreError};

/// Default spacing, in bytes of decompressed OUTPUT, between saved checkpoints.
/// A `read_at` re-inflates at most this many bytes to reach any offset.
pub(crate) const DEFAULT_CHECKPOINT_INTERVAL: u64 = 8 * 1024 * 1024;

/// Ceiling on total decompressed size while building the index (decompression-bomb
/// guard). Mirrors `codec::MAX_BUFFERED_DECODE`.
const MAX_DECODE: u64 = 4 * 1024 * 1024 * 1024;

/// Ceiling on the total bytes held by the checkpoint index. Each checkpoint blob
/// is a window snapshot (~65-131 KiB); this bounds index memory even when a tiny
/// interval is requested.
const MAX_INDEX_BYTES: usize = 512 * 1024 * 1024;

/// Working buffer sizes for feeding compressed input and draining output.
const IO_CHUNK: usize = 128 * 1024;

/// One saved decoder state: restore this to resume decoding near `output_offset`.
struct Checkpoint {
    /// Decompressed-output offset at which this checkpoint resumes producing bytes.
    output_offset: u64,
    /// Absolute backing-file offset of the next compressed byte to feed.
    input_offset: u64,
    /// Serialized inflater state (`None` == the stream start: a fresh inflater).
    blob: Option<Vec<u8>>,
}

/// A checkpoint index over one genuinely-compressed Deflate64 entry.
pub(crate) struct Deflate64Index {
    /// Entry name (diagnostics only).
    name: String,
    /// Absolute file offset one past the entry's compressed data.
    data_end: u64,
    /// The entry's decompressed length.
    uncompressed_size: u64,
    /// Checkpoints, strictly increasing by `output_offset`; the first is always
    /// the stream start (`output_offset == 0`, `blob == None`).
    checkpoints: Vec<Checkpoint>,
}

impl Deflate64Index {
    /// Number of indexed checkpoints (always >= 1: the stream start).
    pub(crate) fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Read up to `buf.len()` uncompressed bytes starting at `offset`, restoring
    /// the nearest checkpoint and skipping forward. Takes `&self` (positioned
    /// reads), so independent reads run lock-free in parallel.
    pub(crate) fn read_at(&self, file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        // STUB (RED): not yet implemented.
        let _ = (file, buf, offset);
        Ok(0)
    }
}

/// Decode the member once, capturing a checkpoint every ~`interval` output bytes.
pub(crate) fn build_index(
    file: &File,
    name: &str,
    data_start: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    interval: u64,
) -> Result<Deflate64Index, ZipCoreError> {
    // STUB (RED): only the start checkpoint, no decode.
    let _ = (compressed_size, interval);
    Ok(Deflate64Index {
        name: name.to_string(),
        data_end: data_start + compressed_size,
        uncompressed_size,
        checkpoints: vec![Checkpoint {
            output_offset: 0,
            input_offset: data_start,
            blob: None,
        }],
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::{CompressionMethod, ZipArchive};
    use std::io::Read;

    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/codecs/seek-deflate64.zip"
    ));

    /// Reconstruct the fixture's known content (the documented generator), so the
    /// oracle is independently-derived ground truth, not just self-consistency.
    fn known_content() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..4096u32 {
            v.extend_from_slice(
                format!(
                    "{i:08} the quick brown fox jumps over the lazy dog - lorem ipsum dolor sit amet consectetur\n"
                )
                .as_bytes(),
            );
        }
        v
    }

    struct Prepared {
        _tmp: tempfile::NamedTempFile,
        file: File,
        data_start: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        oracle: Vec<u8>,
    }

    fn prepare() -> Prepared {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), FIXTURE).unwrap();

        let mut ar = ZipArchive::new(File::open(tmp.path()).unwrap()).unwrap();
        let mut entry = ar.by_name("bigfile.txt").unwrap();
        assert_eq!(entry.compression(), CompressionMethod::Deflate64);
        let data_start = entry.data_start();
        let compressed_size = entry.compressed_size();
        let uncompressed_size = entry.size();
        let mut oracle = Vec::new();
        entry.read_to_end(&mut oracle).unwrap();
        drop(entry);
        drop(ar);

        // The full sequential decode must match the independently-known content.
        assert_eq!(oracle.len() as u64, uncompressed_size);
        assert_eq!(oracle, known_content(), "full decode vs known generator");

        let file = File::open(tmp.path()).unwrap();
        Prepared {
            _tmp: tmp,
            file,
            data_start,
            compressed_size,
            uncompressed_size,
            oracle,
        }
    }

    #[test]
    fn read_at_matches_full_decompress_oracle_across_checkpoints() {
        let p = prepare();
        // Lower the interval so a handful of checkpoints exist and a seek crosses
        // >= 1 of them (the committed fixture is small).
        let interval = 64 * 1024;
        let index = build_index(
            &p.file,
            "bigfile.txt",
            p.data_start,
            p.compressed_size,
            p.uncompressed_size,
            interval,
        )
        .unwrap();

        // Multiple checkpoints, and a mid-file offset genuinely crosses >= 1.
        assert!(
            index.checkpoint_count() >= 2,
            "expected multiple checkpoints, got {}",
            index.checkpoint_count()
        );
        let second_ckpt = index.checkpoints[1].output_offset;
        let mid = p.uncompressed_size / 2;
        assert!(
            second_ckpt < mid,
            "mid offset {mid} must sit past the 2nd checkpoint {second_ckpt}"
        );

        let cases: [(u64, usize); 5] = [
            (0, 100),                           // start
            (mid, 4096),                        // crosses several checkpoints
            (interval + 123, 5000),             // lands mid-checkpoint, spans blocks
            (p.uncompressed_size - 1, 1),       // last byte
            (p.uncompressed_size - 3000, 4000), // short read at EOF (buf > remaining)
        ];
        for (off, len) in cases {
            let mut buf = vec![0u8; len];
            let n = index.read_at(&p.file, &mut buf, off).unwrap();
            let end = (off as usize + len).min(p.oracle.len());
            assert_eq!(
                &buf[..n],
                &p.oracle[off as usize..end],
                "seek mismatch at off={off} len={len}"
            );
        }

        // A backward seek after a forward seek returns correct bytes (independent
        // &self reads, no shared cursor).
        let mut fwd = vec![0u8; 2000];
        let nf = index
            .read_at(&p.file, &mut fwd, p.uncompressed_size - 3000)
            .unwrap();
        assert_eq!(
            &fwd[..nf],
            &p.oracle
                [(p.uncompressed_size - 3000) as usize..(p.uncompressed_size - 3000) as usize + nf]
        );
        let mut back = vec![0u8; 2000];
        let nb = index.read_at(&p.file, &mut back, 500).unwrap();
        assert_eq!(&back[..nb], &p.oracle[500..500 + nb]);
    }

    #[test]
    fn read_at_past_end_and_empty_buf_return_zero() {
        let p = prepare();
        let index = build_index(
            &p.file,
            "bigfile.txt",
            p.data_start,
            p.compressed_size,
            p.uncompressed_size,
            64 * 1024,
        )
        .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            index
                .read_at(&p.file, &mut buf, p.uncompressed_size)
                .unwrap(),
            0
        );
        assert_eq!(index.read_at(&p.file, &mut [], 0).unwrap(), 0);
    }
}
