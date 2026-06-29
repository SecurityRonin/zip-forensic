//! Native pure-Rust container parser — differential vs the `zip` crate (tier-1
//! oracle): every entry's metadata and decoded bytes must match zip-rs exactly.
//!
//! These tests drive the `zip_core::ZipArchive` surface that REPLACES our use of
//! zip-rs to locate/read entries. zip-rs stays a dev-dependency oracle only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod as OracleMethod, ZipWriter};

use zip_core::{CompressionMethod, ZipArchive};

/// Build a multi-entry zip in memory with zip-rs (the oracle writer).
fn build_oracle_zip(entries: &[(&str, OracleMethod, &[u8])]) -> Vec<u8> {
    let mut zw = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, method, data) in entries {
        let opts = SimpleFileOptions::default().compression_method(*method);
        zw.start_file(*name, opts).unwrap();
        zw.write_all(data).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// Decode an entry with the zip-rs oracle.
fn oracle_decode(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut ar = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut e = ar.by_name(name).unwrap();
    let mut out = Vec::new();
    e.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn parses_entry_count_and_names_like_oracle() {
    let payload_a = b"hello, forensic world".to_vec();
    let payload_b: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
    let bytes = build_oracle_zip(&[
        ("alpha.txt", OracleMethod::Stored, &payload_a),
        ("dir/beta.bin", OracleMethod::Deflated, &payload_b),
    ]);

    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(ar.len(), 2);
    assert!(!ar.is_empty());

    let names: Vec<String> = ar.file_names().map(str::to_string).collect();
    assert!(names.contains(&"alpha.txt".to_string()));
    assert!(names.contains(&"dir/beta.bin".to_string()));

    // Metadata via by_index mirrors the oracle.
    let e0 = ar.by_index(0).unwrap();
    assert_eq!(e0.name(), "alpha.txt");
    assert_eq!(e0.compression(), CompressionMethod::Stored);
    assert_eq!(e0.size(), payload_a.len() as u64);
}

#[test]
fn stored_entry_decodes_byte_identical_to_oracle() {
    let payload: Vec<u8> = (0..40_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let bytes = build_oracle_zip(&[("image.bin", OracleMethod::Stored, &payload)]);

    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let mut e = ar.by_name("image.bin").unwrap();
    assert_eq!(e.compression(), CompressionMethod::Stored);
    assert_eq!(e.size(), payload.len() as u64);
    assert_eq!(e.compressed_size(), payload.len() as u64);

    let mut decoded = Vec::new();
    e.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded, oracle_decode(&bytes, "image.bin"));
}

#[test]
fn deflate_entry_decodes_byte_identical_to_oracle() {
    // Compressible payload so zip-rs actually emits Huffman deflate blocks.
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i / 97) as u8).collect();
    let bytes = build_oracle_zip(&[("data.bin", OracleMethod::Deflated, &payload)]);

    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let mut e = ar.by_name("data.bin").unwrap();
    assert_eq!(e.compression(), CompressionMethod::Deflated);

    let mut decoded = Vec::new();
    e.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(decoded, oracle_decode(&bytes, "data.bin"));
}

#[test]
fn data_start_points_at_first_payload_byte() {
    let payload = b"positioned-window".to_vec();
    let bytes = build_oracle_zip(&[("w.bin", OracleMethod::Stored, &payload)]);

    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let e = ar.by_name("w.bin").unwrap();
    let ds = e.data_start() as usize;
    // For a Stored entry, the bytes at data_start ARE the payload (in-place window).
    assert_eq!(&bytes[ds..ds + payload.len()], &payload[..]);
}

#[test]
fn missing_entry_is_an_error_not_a_panic() {
    let bytes = build_oracle_zip(&[("only.txt", OracleMethod::Stored, b"x")]);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(ar.by_name("nope.txt").is_err());
    assert!(ar.by_index(99).is_err());
}

#[test]
fn crc_mismatch_fails_loud_on_eof() {
    // Corrupt a Stored entry's payload byte so the CRC check must fire at EOF.
    let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
    let mut bytes = build_oracle_zip(&[("doc.txt", OracleMethod::Stored, &payload)]);

    // Find the payload in the file (Stored => verbatim) and flip a byte.
    let pos = bytes
        .windows(payload.len())
        .position(|w| w == &payload[..])
        .expect("payload present verbatim in stored entry");
    bytes[pos] ^= 0xFF;

    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut e = ar.by_name("doc.txt").unwrap();
    let mut decoded = Vec::new();
    let res = e.read_to_end(&mut decoded);
    assert!(
        res.is_err(),
        "corrupt payload must fail the CRC check, not return silently-wrong bytes"
    );
}
