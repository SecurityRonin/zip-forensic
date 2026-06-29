//! Decompression dispatch — pure-Rust decoders only, decompress-only.
//!
//! Each entry's compressed bytes arrive as an `io::Take<&mut R>` limited to the
//! central-directory compressed size; the decoder yields decompressed bytes.

use std::io::{self, Read, Take};

use crate::archive::CompressionMethod;
use crate::ZipCoreError;

/// A per-entry decoder over the limited compressed stream.
pub(crate) enum Decoder<'a, R: Read> {
    /// Method 0: raw passthrough.
    Stored(Take<&'a mut R>),
    /// Method 8: classic DEFLATE via flate2's pure-Rust (`miniz_oxide`) backend.
    Deflate(flate2::read::DeflateDecoder<Take<&'a mut R>>),
}

impl<'a, R: Read> Decoder<'a, R> {
    pub(crate) fn new(
        method: CompressionMethod,
        input: Take<&'a mut R>,
    ) -> Result<Self, ZipCoreError> {
        match method {
            CompressionMethod::Stored => Ok(Self::Stored(input)),
            CompressionMethod::Deflated => {
                Ok(Self::Deflate(flate2::read::DeflateDecoder::new(input)))
            }
            other => Err(ZipCoreError::UnsupportedMethod(other)),
        }
    }
}

impl<R: Read> Read for Decoder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stored(r) => r.read(buf),
            Self::Deflate(r) => r.read(buf),
        }
    }
}
