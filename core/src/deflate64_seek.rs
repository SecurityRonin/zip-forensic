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
        if offset >= self.uncompressed_size || buf.is_empty() {
            return Ok(0);
        }
        let want = (self.uncompressed_size - offset).min(buf.len() as u64) as usize;

        // Nearest checkpoint at or before `offset`. `checkpoints[0].output_offset`
        // is 0, so `partition_point` is always >= 1 and `ci - 1` is in range.
        let ci = self
            .checkpoints
            .partition_point(|c| c.output_offset <= offset);
        let cp = &self.checkpoints[ci - 1];

        let mut inflater = Box::new(InflaterManaged::new());
        let start_out = match &cp.blob {
            None => 0,
            Some(blob) => {
                let Some(pos) = inflater.restore_from_checkpoint(blob) else {
                    return Err(io::Error::other("deflate64 restore failed")); // cov:unreachable: an in-process checkpoint() blob always restores
                };
                pos.output_bytes_already_returned
            }
        };
        debug_assert_eq!(start_out, cp.output_offset);

        let mut raw = RawInflate::new(file, cp.input_offset, self.data_end, inflater);

        // Skip forward from the checkpoint's resume point to `offset`.
        let mut to_skip = offset - start_out;
        let mut scratch = vec![0u8; IO_CHUNK];
        while to_skip > 0 {
            let chunk = to_skip.min(scratch.len() as u64) as usize;
            let n = raw.read(&mut scratch[..chunk])?;
            if n == 0 {
                return Err(io::Error::other("deflate64 stream truncated")); // cov:unreachable: build_index verified full decode to uncompressed_size
            }
            to_skip -= n as u64;
        }

        // Fill the caller's buffer (short only at the genuine end of the entry).
        let mut filled = 0usize;
        while filled < want {
            let n = raw.read(&mut buf[filled..want])?;
            if n == 0 {
                break; // cov:unreachable: want is clamped to uncompressed_size - offset
            }
            filled += n;
        }
        Ok(filled)
    }
}

/// Drives an `InflaterManaged` over a bounded compressed range of the backing
/// file, producing decompressed output. Used both to build the index and to
/// resume from a restored checkpoint.
struct RawInflate<'f> {
    file: &'f File,
    /// Next absolute compressed byte to read.
    file_pos: u64,
    /// One past the entry's compressed data.
    data_end: u64,
    inflater: Box<InflaterManaged>,
    in_buf: Vec<u8>,
    in_start: usize,
    in_end: usize,
}

impl<'f> RawInflate<'f> {
    fn new(file: &'f File, file_pos: u64, data_end: u64, inflater: Box<InflaterManaged>) -> Self {
        Self {
            file,
            file_pos,
            data_end,
            inflater,
            in_buf: vec![0u8; IO_CHUNK],
            in_start: 0,
            in_end: 0,
        }
    }

    /// Produce up to `out.len()` decompressed bytes. Returns 0 at end of stream.
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0); // cov:unreachable: callers always pass a non-empty buffer
        }
        loop {
            if self.in_start == self.in_end {
                let avail = (self.data_end - self.file_pos).min(self.in_buf.len() as u64) as usize;
                if avail > 0 {
                    pread_exact(self.file, &mut self.in_buf[..avail], self.file_pos)?;
                    self.file_pos += avail as u64;
                    self.in_start = 0;
                    self.in_end = avail;
                }
            }
            let no_more_input = self.in_start == self.in_end;
            let res = self
                .inflater
                .inflate(&self.in_buf[self.in_start..self.in_end], out);
            if res.data_error {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid deflate64 stream",
                ));
            }
            self.in_start += res.bytes_consumed;
            if res.bytes_written > 0 {
                return Ok(res.bytes_written);
            }
            if self.inflater.finished() {
                return Ok(0);
            }
            if no_more_input && res.bytes_consumed == 0 {
                // No input left and no progress: the stream is truncated.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of deflate64 stream",
                ));
            }
            // Otherwise: consumed header/bits without emitting yet — loop for more.
        }
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
    build_index_capped(
        file,
        name,
        data_start,
        compressed_size,
        uncompressed_size,
        interval,
        Caps::DEFAULT,
    )
}

/// Safety caps for [`build_index_capped`], parameterized so both guards are
/// exercised from committed bytes with tiny values.
#[derive(Clone, Copy)]
struct Caps {
    /// Ceiling on total decompressed size (decompression-bomb guard).
    max_decode: u64,
    /// Ceiling on total checkpoint-index bytes held in memory.
    max_index_bytes: usize,
}

impl Caps {
    const DEFAULT: Caps = Caps {
        max_decode: MAX_DECODE,
        max_index_bytes: MAX_INDEX_BYTES,
    };
}

/// `build_index` with the safety caps as a parameter.
fn build_index_capped(
    file: &File,
    name: &str,
    data_start: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    interval: u64,
    caps: Caps,
) -> Result<Deflate64Index, ZipCoreError> {
    let interval = interval.max(1);
    let data_end = data_start + compressed_size;

    // The first checkpoint is always the stream start: a fresh inflater fed from
    // `data_start`, producing output from offset 0.
    let mut checkpoints = vec![Checkpoint {
        output_offset: 0,
        input_offset: data_start,
        blob: None,
    }];
    let mut last_output_offset = 0u64;
    let mut index_bytes = 0usize;

    let mut raw = RawInflate::new(file, data_start, data_end, Box::new(InflaterManaged::new()));
    let mut out_buf = vec![0u8; IO_CHUNK];
    let mut total_out = 0u64;
    let mut next_at = interval;

    loop {
        let n = raw
            .read(&mut out_buf)
            .map_err(|e| ZipCoreError::Malformed {
                entry: name.to_string(),
                reason: format!("deflate64 decode failed while indexing: {e}"),
            })?;
        if n == 0 {
            break; // clean end of stream
        }
        total_out += n as u64;
        if total_out > caps.max_decode {
            return Err(ZipCoreError::Malformed {
                entry: name.to_string(),
                reason: format!(
                    "decompressed output exceeds the {}-byte cap",
                    caps.max_decode
                ),
            });
        }

        // Capture a checkpoint once enough new output has accumulated. Only one
        // state exists per position, so a single capture per crossing is correct.
        if total_out >= next_at {
            match raw.inflater.checkpoint() {
                Some((blob, pos)) => {
                    let output_offset = pos.output_bytes_already_returned;
                    if output_offset > last_output_offset {
                        index_bytes += blob.len();
                        if index_bytes > caps.max_index_bytes {
                            return Err(ZipCoreError::Malformed {
                                entry: name.to_string(),
                                reason: format!(
                                    "deflate64 seek index exceeds the {}-byte cap",
                                    caps.max_index_bytes
                                ),
                            });
                        }
                        checkpoints.push(Checkpoint {
                            output_offset,
                            input_offset: data_start + pos.input_bytes_to_skip,
                            blob: Some(blob),
                        });
                        last_output_offset = output_offset;
                    }
                    next_at = output_offset.max(total_out) + interval;
                }
                None => {
                    // No restorable state at this instant (e.g. mid-header); retry
                    // after more output rather than spinning on every call.
                    next_at = total_out + interval;
                }
            }
        }
    }

    if total_out != uncompressed_size {
        return Err(ZipCoreError::Malformed {
            entry: name.to_string(),
            reason: format!(
                "deflate64 decoded {total_out} bytes != entry uncompressed size {uncompressed_size}"
            ),
        });
    }

    Ok(Deflate64Index {
        data_end,
        uncompressed_size,
        checkpoints,
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
        let n_ckpt = index.checkpoint_count();
        assert!(n_ckpt >= 2, "expected multiple checkpoints, got {n_ckpt}");
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

    /// Write raw bytes to a temp file and open it (for crafted malformed streams).
    fn temp_with(bytes: &[u8]) -> (tempfile::NamedTempFile, File) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let file = File::open(tmp.path()).unwrap();
        (tmp, file)
    }

    #[test]
    fn build_index_rejects_corrupt_stream() {
        // 0xFF bytes => bfinal=1, btype=3 (reserved) => the inflater data-errors.
        let (_t, file) = temp_with(&[0xFFu8; 64]);
        let err = build_index_capped(&file, "x", 0, 64, 1000, 4096, Caps::DEFAULT);
        assert!(matches!(err, Err(ZipCoreError::Malformed { .. })));
    }

    #[test]
    fn build_index_rejects_truncated_stream() {
        // One non-final stored block, then the stream ends: more blocks expected.
        let comp = [&[0x00u8, 0x05, 0x00, 0xFA, 0xFF][..], b"hello"].concat();
        let (_t, file) = temp_with(&comp);
        let err = build_index_capped(&file, "x", 0, comp.len() as u64, 1000, 4096, Caps::DEFAULT);
        assert!(matches!(err, Err(ZipCoreError::Malformed { .. })));
    }

    #[test]
    fn build_index_rejects_size_mismatch() {
        let p = prepare();
        // Declare a wrong uncompressed size: the full decode won't match it.
        let err = build_index_capped(
            &p.file,
            "bigfile.txt",
            p.data_start,
            p.compressed_size,
            p.uncompressed_size + 1,
            64 * 1024,
            Caps::DEFAULT,
        );
        assert!(matches!(err, Err(ZipCoreError::Malformed { .. })));
    }

    #[test]
    fn build_index_enforces_decode_bomb_cap() {
        let p = prepare();
        let err = build_index_capped(
            &p.file,
            "bigfile.txt",
            p.data_start,
            p.compressed_size,
            p.uncompressed_size,
            64 * 1024,
            Caps {
                max_decode: 10,
                max_index_bytes: MAX_INDEX_BYTES,
            },
        );
        assert!(matches!(err, Err(ZipCoreError::Malformed { .. })));
    }

    #[test]
    fn build_index_enforces_index_memory_cap() {
        let p = prepare();
        let err = build_index_capped(
            &p.file,
            "bigfile.txt",
            p.data_start,
            p.compressed_size,
            p.uncompressed_size,
            64 * 1024,
            Caps {
                max_decode: MAX_DECODE,
                max_index_bytes: 1,
            },
        );
        assert!(matches!(err, Err(ZipCoreError::Malformed { .. })));
    }
}
