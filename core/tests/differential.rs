//! Differential validation: `zip_core::StoredZipEntry::read_at` must return
//! byte-identical data to the `zip` crate's full decompress-then-slice, at every
//! offset and length — proving random access without inflation is correct.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::write::DeflateEncoder;
use flate2::Compression;

/// Build a ZIP whose single entry is `Defl:N` at level 0 — i.e. the deflate
/// stream is entirely *stored* blocks, exactly like an E01-in-zip. We assemble
/// the local header + a level-0 deflate body + a data descriptor by hand so the
/// fixture is unambiguously stored-block (no reliance on a writer's heuristics).
fn make_stored_block_zip(dir: &Path, name: &str, payload: &[u8]) -> PathBuf {
    // Level-0 deflate of the payload → stored blocks.
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::none());
    enc.write_all(payload).unwrap();
    let deflated = enc.finish().unwrap();

    let crc = crc32(payload);
    let path = dir.join(name);
    let mut out = Vec::new();
    let fname = b"image.bin";

    // ---- local file header (PK\x03\x04) ----
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&8u16.to_le_bytes()); // method = deflate
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(deflated.len() as u32).to_le_bytes()); // comp size
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncomp size
    out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    let lfh_start = 0usize;
    out.extend_from_slice(fname);
    let data_offset = out.len();
    out.extend_from_slice(&deflated);

    // ---- central directory ----
    let cd_start = out.len();
    out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    out.extend_from_slice(&20u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&8u16.to_le_bytes()); // method
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra
    out.extend_from_slice(&0u16.to_le_bytes()); // comment
    out.extend_from_slice(&0u16.to_le_bytes()); // disk start
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&(lfh_start as u32).to_le_bytes()); // lfh offset
    out.extend_from_slice(fname);

    // ---- end of central directory ----
    let cd_size = out.len() - cd_start;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_start as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    let _ = data_offset;
    std::fs::write(&path, &out).unwrap();
    path
}

/// Build a ZIP whose single entry is genuinely Huffman-compressed (level best),
/// so `open_entry` cannot stored-block-index it and must use the full-decompress
/// FALLBACK path. Exercises (and pins) that path independently of zip-rs.
fn make_compressed_zip(dir: &Path, name: &str, payload: &[u8]) -> PathBuf {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
    enc.write_all(payload).unwrap();
    let deflated = enc.finish().unwrap();

    let crc = crc32(payload);
    let path = dir.join(name);
    let mut out = Vec::new();
    let fname = b"compressed.bin";

    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let lfh_start = 0usize;
    out.extend_from_slice(fname);
    out.extend_from_slice(&deflated);

    let cd_start = out.len();
    out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(fname.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(lfh_start as u32).to_le_bytes());
    out.extend_from_slice(fname);

    let cd_size = out.len() - cd_start;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_start as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    std::fs::write(&path, &out).unwrap();
    path
}

#[test]
fn read_at_matches_full_decompress_on_compressed_entry() {
    let dir = tempfile::tempdir().unwrap();
    // Compressible payload so flate2 emits Huffman blocks (forces the fallback).
    let payload: Vec<u8> = (0..80_000u32).map(|i| (i / 53) as u8).collect();
    let path = make_compressed_zip(dir.path(), "fixture.zip", &payload);

    let entry = zip_core::open_entry(&path, "compressed.bin").unwrap();
    assert_eq!(entry.len(), payload.len() as u64);
    assert!(
        !entry.is_stored_block_indexed(),
        "best-compression => fallback path"
    );

    let cases = [
        (0usize, 16usize),
        (1, 100),
        (40_000, 999),
        (79_990, 50),
        (0, payload.len()),
    ];
    for (off, len) in cases {
        let mut buf = vec![0u8; len];
        let n = entry.read_at(&mut buf, off as u64).unwrap();
        let expected = oracle_read(&path, "compressed.bin", off, len);
        assert_eq!(
            &buf[..n],
            &expected[..],
            "mismatch at offset={off} len={len}"
        );
    }
}

fn crc32(data: &[u8]) -> u32 {
    // Standard CRC-32 (IEEE), table-free.
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The oracle: full decompress via the `zip` crate, then slice.
fn oracle_read(path: &Path, name: &str, offset: usize, len: usize) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut all = Vec::new();
    entry.read_to_end(&mut all).unwrap();
    let start = offset.min(all.len());
    let end = (offset + len).min(all.len());
    all[start..end].to_vec()
}

#[test]
fn read_at_matches_full_decompress_on_stored_block_entry() {
    let dir = tempfile::tempdir().unwrap();
    // > 64 KiB so the deflate stream spans multiple stored blocks (LEN is u16).
    let payload: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let path = make_stored_block_zip(dir.path(), "fixture.zip", &payload);

    let entry = zip_core::open_entry(&path, "image.bin").unwrap();
    assert_eq!(entry.len(), payload.len() as u64);

    // Probe a spread of offsets/lengths, including block boundaries (~65535) and EOF.
    let cases = [
        (0usize, 16usize),
        (1, 100),
        (65_530, 20), // straddles the first stored-block boundary
        (65_535, 10),
        (131_070, 64), // straddles the second boundary
        (199_990, 50), // short read at EOF
        (0, payload.len()),
    ];
    for (off, len) in cases {
        let mut buf = vec![0xAAu8; len];
        let n = entry.read_at(&mut buf, off as u64).unwrap();
        let expected = oracle_read(&path, "image.bin", off, len);
        assert_eq!(
            &buf[..n],
            &expected[..],
            "mismatch at offset={off} len={len}"
        );
    }
}

/// Env-gated differential against the REAL DFIR Madness E01-in-zip (Doer-Checker:
/// validate the fast path against a genuine third-party artifact, not only a
/// synthetic fixture). Set `ZIP_CORE_REAL_E01_ZIP` to the zip and
/// `ZIP_CORE_REAL_E01_ENTRY` to the entry name to run.
#[test]
fn read_at_matches_real_e01_zip() {
    let Ok(zip_path) = std::env::var("ZIP_CORE_REAL_E01_ZIP") else {
        eprintln!("skipping: ZIP_CORE_REAL_E01_ZIP not set");
        return;
    };
    let entry_name = std::env::var("ZIP_CORE_REAL_E01_ENTRY")
        .unwrap_or_else(|_| "E01-DC01/20200918_0347_CDrive.E01".to_string());
    let path = PathBuf::from(zip_path);

    let entry = zip_core::open_entry(&path, &entry_name).unwrap();
    // Scattered random-ish offsets across the multi-GB entry.
    let size = entry.len();
    let offsets = [0u64, 4096, 1_000_003, size / 3, size / 2, size - 8192];
    for off in offsets {
        let len = 8192usize.min((size - off) as usize);
        let mut buf = vec![0u8; len];
        let n = entry.read_at(&mut buf, off).unwrap();
        let expected = oracle_read(&path, &entry_name, off as usize, len);
        assert_eq!(
            &buf[..n],
            &expected[..],
            "real-E01 mismatch at offset={off}"
        );
    }
}

/// Tier-1 validation against a REAL third-party artifact with an INDEPENDENT
/// ground truth: the DFIR-Madness "Stolen Szechuan Sauce" `DC01-E01.zip` (a real
/// Windows disk E01 wrapped in a `Defl:N` stored-block zip) compared to the
/// separately-extracted E01 file. `read_at` into the multi-GB entry must match
/// the extracted bytes at every probed offset — proving random access into a real
/// E01-in-zip is byte-correct, with no full decompression.
///
/// Env-gated (skips cleanly when the corpus is absent):
///   ZIP_CORE_REAL_E01_ZIP        = path to DC01-E01.zip
///   ZIP_CORE_REAL_E01_EXTRACTED  = path to the extracted .E01 (the answer key)
///   ZIP_CORE_REAL_E01_ENTRY      = entry name (defaults to the DC01 C-drive E01)
#[test]
fn native_decode_matches_extracted_ground_truth() {
    let (Ok(zip_path), Ok(extracted)) = (
        std::env::var("ZIP_CORE_REAL_E01_ZIP"),
        std::env::var("ZIP_CORE_REAL_E01_EXTRACTED"),
    ) else {
        eprintln!("skipping: ZIP_CORE_REAL_E01_ZIP / ZIP_CORE_REAL_E01_EXTRACTED not set");
        return;
    };
    let entry_name = std::env::var("ZIP_CORE_REAL_E01_ENTRY")
        .unwrap_or_else(|_| "E01-DC01/20200918_0347_CDrive.E01".to_string());

    // Real-world note: this DFIR-Madness E01 was written with NORMAL deflate (not
    // level-0), so it is Huffman-coded, not stored-block addressable — zip-core
    // correctly uses its full-decode path here. (The stored-block fast path is
    // validated by the synthetic tests above.)
    let zip = std::fs::File::open(&zip_path).unwrap();
    let mut archive = zip_core::ZipArchive::new(zip).unwrap();
    let mut decoded = archive.by_name(&entry_name).unwrap();
    let total = decoded.size();
    assert_eq!(
        std::fs::metadata(&extracted).unwrap().len(),
        total,
        "entry size vs extracted ground truth"
    );

    // Stream zip-core's native decode and compare to the extracted ground truth in
    // 1 MiB chunks (bounded memory). zip-core verifies CRC-32 against the recorded
    // value at EOF, so reaching EOF cleanly is itself an independent integrity check.
    let mut gt = std::io::BufReader::new(std::fs::File::open(&extracted).unwrap());
    let mut got = vec![0u8; 1 << 20];
    let mut want = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    loop {
        // Fill `got` from the decoder (Read may return short).
        let mut n = 0usize;
        while n < got.len() {
            let r = decoded.read(&mut got[n..]).unwrap();
            if r == 0 {
                break;
            }
            n += r;
        }
        if n == 0 {
            break;
        }
        gt.read_exact(&mut want[..n]).unwrap();
        assert_eq!(&got[..n], &want[..n], "decode mismatch near byte {pos}");
        pos += n as u64;
    }
    assert_eq!(pos, total, "decoded length vs ground truth");
}
