//! Container-structure tests: Zip64 extended info, data descriptors (GP flag bit
//! 3), and adversarial/bomb-safety inputs. Fixtures from Python `zipfile` (see
//! tests/data/README.md); ground truth is the deterministic payload.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use zip_core::{CompressionMethod, ZipArchive};

fn payload() -> Vec<u8> {
    (0..3000u32).map(|i| (i * 37) as u8).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/structure"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn decode(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut ar = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut e = ar.by_name(name).unwrap();
    let mut out = Vec::new();
    e.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn zip64_forced_real_tool_archive_decodes() {
    // Python force_zip64: zip64 extra in the LFH, but the CD keeps real 32-bit
    // sizes. A real-tool smoke that the LFH extra-length is honored for data_start.
    let bytes = fixture("zip64.zip");
    let p = payload();
    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let e = ar.by_name("file.bin").unwrap();
    assert_eq!(e.size(), p.len() as u64);
    assert_eq!(e.compression(), CompressionMethod::Stored);
    drop(e);
    assert_eq!(decode(&bytes, "file.bin"), p);
}

#[test]
fn zip64_central_dir_extra_field_resolves_sizes() {
    // CD base size fields are 0xFFFFFFFF sentinels; real sizes live in the Zip64
    // extended-information extra field (header id 0x0001) and must be resolved.
    let bytes = fixture("zip64_cd_extra.zip");
    let p = payload();
    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let e = ar.by_name("z64.bin").unwrap();
    assert_eq!(
        e.size(),
        p.len() as u64,
        "uncompressed size from zip64 extra"
    );
    assert_eq!(e.compressed_size(), p.len() as u64);
    drop(e);
    assert_eq!(decode(&bytes, "z64.bin"), p);
}

#[test]
fn zip64_eocd_record_resolves_central_dir() {
    // The 32-bit EOCD has sentinel offset/count; the real central-directory offset
    // and entry count come from the Zip64 EOCD record via its locator.
    let bytes = fixture("zip64_eocd.zip");
    let p = payload();
    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    assert_eq!(ar.len(), 1, "entry count from zip64 EOCD");
    let e = ar.by_name("z64.bin").unwrap();
    assert_eq!(e.size(), p.len() as u64);
    drop(e);
    assert_eq!(decode(&bytes, "z64.bin"), p);
}

#[test]
fn data_descriptor_entry_decodes_from_central_directory() {
    let bytes = fixture("datadesc.zip");
    let p = payload();
    let mut ar = ZipArchive::new(Cursor::new(bytes.clone())).unwrap();
    let e = ar.by_name("dd.bin").unwrap();
    assert_ne!(
        e.flags() & 0x0008,
        0,
        "fixture must have the data-descriptor flag"
    );
    assert_eq!(e.size(), p.len() as u64);
    drop(e);
    assert_eq!(decode(&bytes, "dd.bin"), p);
}

#[test]
fn truncated_archive_errors_not_panics() {
    let bytes = fixture("zip64.zip");
    // Lop off the tail (EOCD region) — must error cleanly, never panic.
    let truncated = &bytes[..bytes.len() / 2];
    assert!(ZipArchive::new(Cursor::new(truncated.to_vec())).is_err());
    // Empty input.
    assert!(ZipArchive::new(Cursor::new(Vec::<u8>::new())).is_err());
}
