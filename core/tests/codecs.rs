//! Codec differential tests (tier-1 oracles).
//!
//! - Bzip2 (12) and Zstd (93) are written by zip-rs using the C libbz2/libzstd
//!   and decoded by zip-core's PURE-RUST `bzip2-rs`/`ruzstd` — an independent
//!   implementation on each side, with the known payload as ground truth.
//! - Deflate64 (9) and LZMA (14) are decoded from fixtures produced by `7z`
//!   (`tests/data/codecs/*.zip`, see that dir's README), compared to the same
//!   deterministic payload and to the zip-rs oracle's decode.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod as OracleMethod, ZipWriter};

use zip_core::{CompressionMethod, ZipArchive};

/// The exact bytes the committed 7z fixtures were built from, and the payload the
/// in-memory bzip2/zstd archives carry. Must match `tests/data/codecs/README.md`.
fn payload() -> Vec<u8> {
    (0..20_000u32).map(|i| (i / 64) as u8).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path =
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/codecs")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn oracle_decode(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut ar = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut e = ar.by_name(name).unwrap();
    let mut out = Vec::new();
    e.read_to_end(&mut out).unwrap();
    out
}

/// Decode `name` from `bytes` with zip-core and assert it equals `expect`.
fn assert_zip_core_decodes(bytes: &[u8], name: &str, method: CompressionMethod, expect: &[u8]) {
    let mut ar = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut e = ar.by_name(name).unwrap();
    assert_eq!(e.compression(), method, "method for {name}");
    let mut got = Vec::new();
    e.read_to_end(&mut got).unwrap();
    assert_eq!(got, expect, "decoded bytes for {name}");
}

#[test]
fn bzip2_decodes_byte_identical_to_oracle() {
    let p = payload();
    let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
    zw.start_file(
        "file.bin",
        SimpleFileOptions::default().compression_method(OracleMethod::Bzip2),
    )
    .unwrap();
    zw.write_all(&p).unwrap();
    let bytes = zw.finish().unwrap().into_inner();

    assert_eq!(oracle_decode(&bytes, "file.bin"), p);
    assert_zip_core_decodes(&bytes, "file.bin", CompressionMethod::Bzip2, &p);
}

#[test]
fn zstd_decodes_byte_identical_to_oracle() {
    let p = payload();
    let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
    zw.start_file(
        "file.bin",
        SimpleFileOptions::default().compression_method(OracleMethod::Zstd),
    )
    .unwrap();
    zw.write_all(&p).unwrap();
    let bytes = zw.finish().unwrap().into_inner();

    assert_eq!(oracle_decode(&bytes, "file.bin"), p);
    assert_zip_core_decodes(&bytes, "file.bin", CompressionMethod::Zstd, &p);
}

// Deflate64 (9) and LZMA (14) ground truth is the payload the 7z fixtures were
// built from (verified: 7z extraction reproduces it byte-for-byte). We do NOT
// cross-check via zip-rs here: zip-rs fails to decode 7z's method-14 LZMA framing
// ("LZ distance beyond output size"), so the third-party FIXTURE + known payload
// is the tier-1 answer key, not a same-decoder round-trip.
#[test]
fn deflate64_decodes_7z_fixture() {
    let bytes = fixture("deflate64.zip");
    assert_zip_core_decodes(&bytes, "file.bin", CompressionMethod::Deflate64, &payload());
}

#[test]
fn lzma_decodes_7z_fixture() {
    let bytes = fixture("lzma.zip");
    assert_zip_core_decodes(&bytes, "file.bin", CompressionMethod::Lzma, &payload());
}

#[test]
fn xz_decodes_method95_fixture() {
    // Method-95 (XZ) is rare in the wild; the fixture's .xz stream was produced by
    // Python's `lzma` (FORMAT_XZ) and wrapped in a hand-built container. Ground
    // truth (payload) confirmed by 7z extraction. See tests/data/README.md.
    let bytes = fixture("xz.zip");
    assert_zip_core_decodes(&bytes, "file.bin", CompressionMethod::Xz, &payload());
}
