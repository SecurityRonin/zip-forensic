//! Decompression dispatch — pure-Rust decoders only, decompress-only.
//!
//! Each entry's compressed bytes arrive as an `io::Take<&mut R>` limited to the
//! central-directory compressed size; the decoder yields decompressed bytes.
//!
//! Stored / Deflate / Deflate64 stay streaming (these are the fleet-critical,
//! potentially multi-GB paths). Bzip2 / Zstd / LZMA / XZ decode one-shot into a
//! buffer — they are rarer and smaller, and the genuinely-huge path is the
//! zero-copy stored-block `read_at`, not full decode.

use std::io::{self, BufReader, Cursor, Read, Take};

use crate::archive::CompressionMethod;
use crate::{FormatError, ZipCoreError};

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
                Ok(Self::Buffered(Cursor::new(read_all(&mut dec)?)))
            }
            CompressionMethod::Zstd => {
                let mut dec = ruzstd::decoding::StreamingDecoder::new(input)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Self::Buffered(Cursor::new(read_all(&mut dec)?)))
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
                let mut out = Vec::new();
                lzma_rs::xz_decompress(&mut Cursor::new(raw), &mut out)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                Ok(Self::Buffered(Cursor::new(out)))
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

fn read_all<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
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
    let mut out = Vec::new();
    let options = lzma_rs::decompress::Options {
        unpacked_size: lzma_rs::decompress::UnpackedSize::UseProvided(Some(expected_size)),
        memlimit: None,
        allow_incomplete: false,
    };
    lzma_rs::lzma_decompress_with_options(&mut Cursor::new(body), &mut out, &options)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(out)
}
