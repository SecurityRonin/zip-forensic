//! Coverage of the legacy `open_entry`/`StoredZipEntry`/`index_stored_blocks`
//! edge + error paths and the codec error arms, via crafted inputs. Each test
//! drives a specific branch that the differential/oracle suites don't reach.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use zip_core::{CompressionMethod, ZipArchive};

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let m = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & m);
        }
    }
    !crc
}

/// Build a single-entry zip with an explicit method, raw entry bytes, declared
/// uncompressed size and CRC — letting a test craft malformed streams.
fn build_zip(method: u16, comp: &[u8], uncomp_size: u32, crc: u32) -> Vec<u8> {
    let nb = b"e.bin";
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&crc.to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&uncomp_size.to_le_bytes());
    o.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(nb);
    o.extend_from_slice(comp);
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&crc.to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&uncomp_size.to_le_bytes());
    o.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(nb);
    let cd_size = o.len() - cd;
    o.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&(cd_size as u32).to_le_bytes());
    o.extend_from_slice(&(cd as u32).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o
}

fn write_tmp(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.zip");
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

// ---- StoredZipEntry edge methods + Stored (method 0) open_entry ----

#[test]
fn open_entry_stored_method0_and_read_at_edges() {
    let payload = b"in-place stored window payload".to_vec();
    let bytes = build_zip(0, &payload, payload.len() as u32, crc32(&payload));
    let (_d, path) = write_tmp(&bytes);

    let entry = zip_core::open_entry(&path, "e.bin").unwrap();
    assert!(entry.is_stored_block_indexed());
    assert_eq!(entry.block_count(), 1);
    assert!(!entry.is_empty());
    assert_eq!(entry.len(), payload.len() as u64);

    // offset >= size and empty buffer both return 0 (early-return branch).
    let mut buf = [0u8; 8];
    assert_eq!(entry.read_at(&mut buf, 9999).unwrap(), 0);
    assert_eq!(entry.read_at(&mut [], 0).unwrap(), 0);

    let n = entry.read_at(&mut buf, 0).unwrap();
    assert_eq!(&buf[..n], &payload[..n]);
}

// ---- index_stored_blocks malformed/edge branches (method 8) ----

#[test]
fn stored_block_bad_nlen_is_malformed() {
    // bfinal=1, btype=0, LEN=5, NLEN=0xFFFF (not !5) -> LEN/NLEN mismatch.
    let comp = [&[0x01u8, 0x05, 0x00, 0xFF, 0xFF][..], b"hello"].concat();
    let bytes = build_zip(8, &comp, 5, 0);
    let (_d, path) = write_tmp(&bytes);
    assert!(zip_core::open_entry(&path, "e.bin").is_err());
}

#[test]
fn stored_block_overrun_is_malformed() {
    // LEN=255 but only 2 data bytes present -> block overruns the compressed data.
    let comp = [&[0x01u8, 0xFF, 0x00, 0x00, 0xFF][..], b"ab"].concat();
    let bytes = build_zip(8, &comp, 255, 0);
    let (_d, path) = write_tmp(&bytes);
    assert!(zip_core::open_entry(&path, "e.bin").is_err());
}

#[test]
fn stored_block_total_size_mismatch_is_malformed() {
    // One valid 5-byte stored block, but the CD claims 99 uncompressed bytes.
    let comp = [&[0x01u8, 0x05, 0x00, 0xFA, 0xFF][..], b"hello"].concat();
    let bytes = build_zip(8, &comp, 99, crc32(b"hello"));
    let (_d, path) = write_tmp(&bytes);
    assert!(zip_core::open_entry(&path, "e.bin").is_err());
}

#[test]
fn stored_block_no_final_block_falls_back() {
    // bfinal=0 then the stream ends -> not a clean stored run -> fallback path.
    let comp = [&[0x00u8, 0x05, 0x00, 0xFA, 0xFF][..], b"hello"].concat();
    let bytes = build_zip(8, &comp, 5, crc32(b"hello"));
    let (_d, path) = write_tmp(&bytes);
    let entry = zip_core::open_entry(&path, "e.bin").unwrap();
    assert!(
        !entry.is_stored_block_indexed(),
        "incomplete run => fallback"
    );
    assert_eq!(entry.block_count(), 0);
}

// ---- open_entry fallback for a non-deflate method (bzip2 fixture) ----

fn fixture(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/data")).join(rel);
    std::fs::read(path).unwrap()
}

#[test]
fn open_entry_bzip2_uses_fallback_and_reads() {
    let bytes = fixture("codecs/bzip2.zip");
    let (_d, path) = write_tmp(&bytes);
    let entry = zip_core::open_entry(&path, "file.bin").unwrap();
    assert!(!entry.is_stored_block_indexed(), "bzip2 => fallback path");
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i / 64) as u8).collect();
    let mut buf = vec![0u8; 100];
    let n = entry.read_at(&mut buf, 1000).unwrap();
    assert_eq!(&buf[..n], &payload[1000..1000 + n]);
}

// ---- codec error arms ----

fn decode_err(method: u16, comp: &[u8], uncomp_size: u32) -> bool {
    let bytes = build_zip(method, comp, uncomp_size, 0);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    // Buffered codecs decode eagerly in `by_index`; streaming ones fail on read.
    match ar.by_index(0) {
        Err(_) => true,
        Ok(mut e) => {
            let mut out = Vec::new();
            e.read_to_end(&mut out).is_err()
        }
    }
}

#[test]
fn unknown_method_is_unsupported() {
    let bytes = build_zip(99, b"x", 1, 0);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        ar.by_index(0).map(|_| ()),
        Err(zip_core::ZipCoreError::UnsupportedMethod(
            CompressionMethod::Unknown(99)
        ))
    ));
}

#[test]
fn corrupt_codec_streams_error() {
    assert!(decode_err(12, b"not-a-bzip2-stream--padding-padding", 50)); // bzip2
    assert!(decode_err(93, b"not-a-zstd-frame----------padding--", 50)); // zstd
    assert!(decode_err(95, b"not-an-xz-stream----------padding--", 50)); // xz
}

#[test]
fn lzma_wrapper_errors() {
    assert!(decode_err(14, b"abc", 10)); // < 4 bytes -> Truncated
                                         // props length 9 (!= 5) in the 4-byte ZIP wrapper -> Malformed.
    assert!(decode_err(14, &[0x09, 0x14, 0x09, 0x00, 0, 0, 0, 0, 0], 10));
}
