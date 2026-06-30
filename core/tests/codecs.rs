//! Codec decode tests, labelled by validation tier (who chose the scenario, not
//! whether the data is "synthetic"):
//!
//! All decode tests here are **tier-1** — real-world, third-party-authored
//! archives whose ground truth is the reference-CLI decode of the raw stream (an
//! independent oracle we did not author):
//!   - Bzip2 (12): libzip's `testbzip2.zip` (`bunzip2`).
//!   - Zstd (93), Deflate64 (9), LZMA (14), XZ (95): WinZip-produced archives
//!     from the zipdetails corpus (`7zz` / `zstd -d`), each carrying `lorem.txt`.
//!   - Plus a real-world Deflate64 CTF sample and (env-gated) the real
//!     DFIR-Madness E01-in-zip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use zip_core::{CompressionMethod, ZipArchive};

/// The 446-byte lorem payload shared by the WinZip method samples (zstd /
/// deflate64 / lzma / xz), as decoded by the reference CLIs (`7zz` / `zstd -d`).
fn winzip_lorem() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/codecs/realworld-winzip-lorem.txt"
    ))
}

fn fixture(name: &str) -> Vec<u8> {
    let path =
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data/codecs")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
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
fn bzip2_decodes_real_world_libzip_fixture() {
    // libzip regress `testbzip2.zip` (BSD-3): a real bzip2 (method 12) stream.
    // Ground truth = `bunzip2` reference decode of the raw entry (independent
    // oracle, recorded here): "abac-repeat.txt" -> 60 bytes.
    let bytes = fixture("realworld-bzip2-libzip.zip");
    let expected = b"aaaaaaaaaaaaaa\nbbbbbbbbbbbbbb\naaaaaaaaaaaaaa\ncccccccccccccc\n";
    assert_zip_core_decodes(
        &bytes,
        "abac-repeat.txt",
        CompressionMethod::Bzip2,
        expected,
    );
}

// Zstd (93), Deflate64 (9), LZMA (14) and XZ (95) are all validated against real
// WinZip-produced archives from the zipdetails corpus (Artistic-1.0), each
// carrying the same `lorem.txt`. Ground truth = the `7zz` / `zstd -d` reference
// decode (independent oracle), committed as `realworld-winzip-lorem.txt`. We do
// NOT cross-check via zip-rs (it rejects WinZip/7z method-14 LZMA framing) — the
// third-party artifact + reference-CLI answer key is the tier-1 check.
#[test]
fn zstd_decodes_real_world_winzip_fixture() {
    let bytes = fixture("realworld-zstd-winzip.zip");
    assert_zip_core_decodes(&bytes, "lorem.txt", CompressionMethod::Zstd, winzip_lorem());
}

#[test]
fn deflate64_decodes_real_world_winzip_fixture() {
    let bytes = fixture("realworld-deflate64-winzip.zip");
    assert_zip_core_decodes(
        &bytes,
        "lorem.txt",
        CompressionMethod::Deflate64,
        winzip_lorem(),
    );
}

#[test]
fn lzma_decodes_real_world_winzip_fixture() {
    let bytes = fixture("realworld-lzma-winzip.zip");
    assert_zip_core_decodes(&bytes, "lorem.txt", CompressionMethod::Lzma, winzip_lorem());
}

#[test]
fn xz_decodes_real_world_winzip_fixture() {
    let bytes = fixture("realworld-xz-winzip.zip");
    assert_zip_core_decodes(&bytes, "lorem.txt", CompressionMethod::Xz, winzip_lorem());
}

/// Tier-1 Deflate64 validation against a REAL third-party artifact: the
/// SecurityNik "TOTAL RECALL" memory-forensics CTF zip — a ~4 GB Windows memory
/// dump compressed with Deflate64 (method 9). zip-core's native decode must
/// reproduce each entry and pass the CRC-32 recorded by the CTF author's tool
/// (the independent answer key), verified at EOF.
///
/// Env-gated: ZIP_CORE_REAL_DEFLATE64_ZIP = path to the zip. The small `.json`
/// entry is always checked; set ZIP_CORE_REAL_DEFLATE64_FULL=1 to also decode the
/// multi-GB `.dmp` (slow).
#[test]
fn deflate64_decodes_real_securitynik_ctf() {
    let Ok(zip_path) = std::env::var("ZIP_CORE_REAL_DEFLATE64_ZIP") else {
        eprintln!("skipping: ZIP_CORE_REAL_DEFLATE64_ZIP not set");
        return;
    };
    let file = std::fs::File::open(&zip_path).unwrap();
    let mut ar = ZipArchive::new(file).unwrap();

    // Every entry is Deflate64; decode the small JSON fully and CRC-verify it.
    // Scoped so the entry (which borrows `ar`) drops before the next is opened.
    {
        let json = "SECURITYNIK-WIN-20231116-235706.json";
        let mut e = ar.by_name(json).unwrap();
        assert_eq!(e.compression(), CompressionMethod::Deflate64);
        let mut out = Vec::new();
        // read_to_end succeeding means CRC-32 matched the CTF author's recorded
        // value (zip-core fails loud on mismatch) — an independent integrity check.
        e.read_to_end(&mut out).unwrap();
        assert_eq!(out.len() as u64, e.size(), "decoded length vs CD size");
    }

    if std::env::var("ZIP_CORE_REAL_DEFLATE64_FULL").is_ok() {
        let dmp = "SECURITYNIK-WIN-20231116-235706.dmp";
        let mut d = ar.by_name(dmp).unwrap();
        assert_eq!(d.compression(), CompressionMethod::Deflate64);
        // Stream to a sink; CRC-32 is verified at EOF.
        let n = std::io::copy(&mut d, &mut std::io::sink()).unwrap();
        assert_eq!(n, d.size(), "decoded length vs CD size");
    }
}
