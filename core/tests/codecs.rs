//! Codec decode tests, labelled by validation tier (who chose the scenario, not
//! whether the data is "synthetic"):
//!
//! - **Tier-1** — Bzip2 (12) and Zstd (93): decoded from real-world,
//!   third-party-authored archives (libzip's `testbzip2.zip`; a WinZip-produced
//!   method-93 zstd from the zipdetails corpus) whose ground truth is the
//!   reference-CLI decode of the raw stream (`bunzip2` / `zstd -d`) — an
//!   independent oracle we did not author. Also tier-1: a real-world Deflate64
//!   CTF sample and (env-gated) the real DFIR-Madness E01-in-zip.
//! - **Tier-2** — Deflate64 (9), LZMA (14), XZ (95): decoded from fixtures the
//!   third-party `7z`/`lzma` tools produced from a payload WE chose, with that
//!   payload (7z-verified) as the answer key. Real encoder bitstream, but our
//!   scenario, so it can miss real-world quirks: tier-2, not tier-1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use zip_core::{CompressionMethod, ZipArchive};

/// The payload the tier-2 7z fixtures (`deflate64`/`lzma`/`xz`) were built from.
/// Must match `tests/data/codecs/README.md`.
fn payload() -> Vec<u8> {
    (0..20_000u32).map(|i| (i / 64) as u8).collect()
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

#[test]
fn zstd_decodes_real_world_winzip_fixture() {
    // WinZip-produced zstd (method 93) from the zipdetails corpus (Artistic-1.0).
    // Ground truth = `zstd -d` reference decode of the raw frame (independent
    // oracle), committed as realworld-zstd-winzip.expected (446-byte lorem).
    let bytes = fixture("realworld-zstd-winzip.zip");
    let expected = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/codecs/realworld-zstd-winzip.expected"
    ));
    assert_zip_core_decodes(&bytes, "lorem.txt", CompressionMethod::Zstd, expected);
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
