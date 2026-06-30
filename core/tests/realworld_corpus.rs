//! Tier-1 validation: real-world, third-party-authored ZIP archives parsed and
//! cross-checked against an independent oracle (`zipdetails`). The archives were
//! authored by the python-libarchive-c maintainers (CC0 1.0) — see
//! `tests/data/README.md` for provenance, hashes, and the oracle-derived
//! ground-truth values asserted below. These are committed fixtures, so the
//! check runs everywhere with no external tool or network dependency.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::ZipArchive;

fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn unicode_zip_unix_timestamps_match_oracle() {
    let mut ar = ZipArchive::new(Cursor::new(load("unicode.zip"))).unwrap();
    let view = ar.structural_view().unwrap();

    // Ground truth from zipdetails (central-directory Extended Timestamp [UT]).
    // The filename is stored in NFD (decomposed) Unicode: "gru" + combining
    // diaeresis U+0308 + "n" — a real-world quirk; the parser surfaces the bytes
    // verbatim rather than normalizing them.
    let expected = [
        ("a/", 1_268_678_396_i32),
        ("a/gru\u{308}n.png", 1_268_678_259),
    ];
    assert_eq!(view.len(), expected.len(), "entry count");
    for (e, (name, mtime)) in view.iter().zip(expected) {
        assert_eq!(e.central.name, name, "entry name");
        assert_eq!(
            e.extra.unix_mtime,
            Some(mtime),
            "unix mtime for {name} must match the zipdetails oracle"
        );
        // The 0x7875 Unix uid/gid extra present in this file is not one we
        // surface; it must be skipped cleanly, not misparsed into a field.
        assert_eq!(e.extra.ntfs_mtime, None);
    }
}

#[test]
fn unicode2_zip_ntfs_filetimes_match_oracle() {
    let mut ar = ZipArchive::new(Cursor::new(load("unicode2.zip"))).unwrap();
    let view = ar.structural_view().unwrap();

    // Ground truth from zipdetails (central-directory NTFS FileTimes, FILETIME
    // ticks). a/ carries sub-second precision (…78 = 490487800 ns).
    // The second entry's filename is genuine real-world mojibake: the NFD bytes
    // `cc 88` (U+0308) were misdecoded as CP437 (╠, ê) and re-encoded to UTF-8.
    // The parser surfaces the exact bytes present, never silently "repairing"
    // them — correct forensic behavior, verified against the file's raw bytes.
    let expected = [
        ("a/", 130_262_190_704_904_878_u64),
        ("a/gru\u{2560}\u{ea}n.png", 129_131_482_600_000_000),
    ];
    assert_eq!(view.len(), expected.len(), "entry count");
    for (e, (name, mtime)) in view.iter().zip(expected) {
        assert_eq!(e.central.name, name, "entry name");
        assert_eq!(
            e.extra.ntfs_mtime,
            Some(mtime),
            "NTFS mtime for {name} must match the zipdetails oracle"
        );
        assert_eq!(e.extra.unix_mtime, None);
    }
}
