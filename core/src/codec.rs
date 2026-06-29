//! Decompression dispatch — pure-Rust decoders only, decompress-only.
//!
//! Each entry's compressed bytes arrive as an `io::Take<&mut R>` limited to the
//! central-directory compressed size; the decoder yields decompressed bytes.
//!
//! Stored / Deflate / Deflate64 stay streaming (these are the fleet-critical,
//! potentially multi-GB paths). Bzip2 / Zstd / LZMA / XZ decode one-shot into a
//! buffer — they are rarer and smaller, and the genuinely-huge path is the
//! zero-copy stored-block `read_at`, not full decode.

use std::io::{self, BufReader, Cursor, Read, Take, Write};

use crate::archive::CompressionMethod;
use crate::{FormatError, ZipCoreError};

/// Upper bound on the output of a buffered (one-shot) codec, guarding against a
/// decompression bomb (tiny input -> huge output). Generous enough for real
/// compressed evidence entries; the genuinely-huge path is the streaming
/// Stored/Deflate read, not these. Exceeding it fails loud.
const MAX_BUFFERED_DECODE: u64 = 4 * 1024 * 1024 * 1024;

/// A per-entry decoder over the limited compressed stream.
pub(crate) enum Decoder<'a, R: Read> {
    /// Method 0: raw passthrough.
    Stored(Take<&'a mut R>),
    /// Method 8: classic DEFLATE via flate2's pure-Rust (`miniz_oxide`) backend.
    Deflate(flate2::read::DeflateDecoder<Take<&'a mut R>>),
    /// Method 9: Deflate64 (pure Rust). `::new` wraps the reader in a `BufReader`.
    Deflate64(deflate64::Deflate64Decoder<BufReader<Take<&'a mut R>>>),
    /// Methods 12/14/93/95: decompressed once into a buffer, then served.
    Buffered(Cursor<Vec<u8>>),
}

impl<'a, R: Read> Decoder<'a, R> {
    pub(crate) fn new(
        method: CompressionMethod,
        expected_size: u64,
        mut input: Take<&'a mut R>,
    ) -> Result<Self, ZipCoreError> {
        match method {
            CompressionMethod::Stored => Ok(Self::Stored(input)),
            CompressionMethod::Deflated => {
                Ok(Self::Deflate(flate2::read::DeflateDecoder::new(input)))
            }
            CompressionMethod::Deflate64 => {
                Ok(Self::Deflate64(deflate64::Deflate64Decoder::new(input)))
            }
            CompressionMethod::Bzip2 => {
                let mut dec = bzip2_rs::DecoderReader::new(input);
                Ok(Self::Buffered(Cursor::new(read_capped(
                    &mut dec,
                    MAX_BUFFERED_DECODE,
                )?)))
            }
            CompressionMethod::Zstd => {
                let mut dec = ruzstd::decoding::StreamingDecoder::new(input)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Self::Buffered(Cursor::new(read_capped(
                    &mut dec,
                    MAX_BUFFERED_DECODE,
                )?)))
            }
            CompressionMethod::Lzma => {
                let mut raw = Vec::new();
                input.read_to_end(&mut raw)?;
                Ok(Self::Buffered(Cursor::new(decode_zip_lzma(
                    &raw,
                    expected_size,
                )?)))
            }
            CompressionMethod::Xz => {
                let mut raw = Vec::new();
                input.read_to_end(&mut raw)?;
                let mut out = CappedWriter::new(MAX_BUFFERED_DECODE);
                lzma_rs::xz_decompress(&mut Cursor::new(raw), &mut out)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Self::Buffered(Cursor::new(out.into_inner())))
            }
            CompressionMethod::Unknown(_) => Err(ZipCoreError::UnsupportedMethod(method)),
        }
    }
}

impl<R: Read> Read for Decoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stored(r) => r.read(buf),
            Self::Deflate(r) => r.read(buf),
            Self::Deflate64(r) => r.read(buf),
            Self::Buffered(r) => r.read(buf),
        }
    }
}

/// Read a decoder fully, but fail loud rather than allocate past `cap` bytes
/// (decompression-bomb guard). Reads at most `cap + 1` and rejects on overflow.
fn read_capped<R: Read>(r: &mut R, cap: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let n = r.take(cap.saturating_add(1)).read_to_end(&mut out)?;
    if n as u64 > cap {
        return Err(io::Error::other(format!(
            "decompressed output exceeds the {cap}-byte cap"
        )));
    }
    Ok(out)
}

/// A `Write` sink that buffers into a `Vec` but errors once `cap` bytes are
/// exceeded — bounds the output of the one-shot LZMA/XZ decoders.
struct CappedWriter {
    buf: Vec<u8>,
    cap: u64,
}

impl CappedWriter {
    fn new(cap: u64) -> Self {
        Self {
            buf: Vec::new(),
            cap,
        }
    }
    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() as u64 + data.len() as u64 > self.cap {
            return Err(io::Error::other(format!(
                "decompressed output exceeds the {}-byte cap",
                self.cap
            )));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decode a ZIP method-14 LZMA entry. The entry data begins with a 4-byte ZIP
/// wrapper (SDK version major/minor + 2-byte properties length); the rest is the
/// standard `[5 props][stream]` with no 8-byte size field — the size comes from
/// the central directory (`expected_size`). (HANDOFF Open Q2.)
fn decode_zip_lzma(data: &[u8], expected_size: u64) -> Result<Vec<u8>, ZipCoreError> {
    if data.len() < 4 {
        return Err(FormatError::Truncated.into());
    }
    let props_len = u16::from_le_bytes([data[2], data[3]]);
    if props_len != 5 {
        return Err(ZipCoreError::Malformed {
            entry: "<lzma>".to_string(),
            reason: format!("unexpected LZMA properties length {props_len} (expected 5)"),
        });
    }
    // After the 4-byte wrapper: [5 props][compressed stream] — exactly what
    // lzma-rs expects when told the unpacked size externally.
    let body = &data[4..];
    let mut out = CappedWriter::new(MAX_BUFFERED_DECODE);
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(expected_size)),
        memlimit: None,
        allow_incomplete: false,
    };
    lzma_rs::lzma_decompress_with_options(&mut Cursor::new(body), &mut out, &options)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn read_capped_rejects_overflow_and_accepts_within() {
        let data = vec![0u8; 100];
        assert!(read_capped(&mut data.as_slice(), 10).is_err());
        assert_eq!(read_capped(&mut data.as_slice(), 200).unwrap().len(), 100);
        assert_eq!(read_capped(&mut data.as_slice(), 100).unwrap().len(), 100);
    }

    #[test]
    fn capped_writer_errors_past_cap() {
        let mut w = CappedWriter::new(8);
        assert_eq!(w.write(b"1234").unwrap(), 4);
        assert!(w.flush().is_ok());
        assert!(w.write(b"56789").is_err());
        assert_eq!(w.into_inner(), b"1234");
    }
}
