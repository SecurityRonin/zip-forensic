//! Tier-1 validation: real-world, third-party-authored ZIP archives parsed and
//! cross-checked against an independent oracle (`zipdetails`). The archives were
//! authored by the python-libarchive-c maintainers (CC0 1.0) and by the Apache
//! Commons Compress project (Apache-2.0, created with WinZip / WinRAR / Info-ZIP)
//! — see `tests/data/README.md` for provenance, hashes, and the oracle-derived
//! ground-truth values asserted below. These are committed fixtures, so the
//! check runs everywhere with no external tool or network dependency.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::{CompressionMethod, ZipArchive, ZipCoreError};

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

#[test]
fn winzip_unicode_path_extra_matches_oracle() {
    // utf8-winzip-test.zip stores each non-ASCII name in CP437 in the main field
    // plus an Info-ZIP Unicode Path extra (0x7075) with the true UTF-8 name.
    // Ground truth: zipdetails "UnicodeName" per central header.
    let mut ar = ZipArchive::new(Cursor::new(load("utf8-winzip-test.zip"))).unwrap();
    let view = ar.structural_view().unwrap();
    let expected = [
        Some("€_for_Dollar.txt"),
        Some("Ölfässer.txt"),
        None, // ascii.txt carries no Unicode Path extra
    ];
    assert_eq!(view.len(), expected.len(), "entry count");
    for (e, want) in view.iter().zip(expected) {
        assert_eq!(
            e.extra.unicode_path.as_deref(),
            want,
            "0x7075 Unicode Path must match the zipdetails oracle"
        );
    }
}

/// Real multi-segment split archives created by independent tools. We hold only
/// the last segment (central directory + EOCD), so enumeration works but every
/// data read must fail loud — never read wrong bytes from the wrong segment.
/// Ground truth from zipdetails: both mark the CD on disk 2 (`disk_number` /
/// `cd_start_disk` == 2).
fn assert_split_fails_loud(file: &str, entries: usize) {
    let mut ar = ZipArchive::new(Cursor::new(load(file))).unwrap();
    assert_eq!(ar.len(), entries, "{file}: entry count");
    assert_eq!(ar.summary().disk_number, 2, "{file}: EOCD this-disk");
    assert_eq!(ar.summary().cd_start_disk, 2, "{file}: EOCD cd-start-disk");
    for i in 0..ar.len() {
        assert!(
            matches!(ar.by_index(i), Err(ZipCoreError::SpannedArchive { .. })),
            "{file}: entry {i} must fail loud (spanned), not read wrong bytes"
        );
    }
}

#[test]
fn winrar_split_archive_fails_loud() {
    assert_split_fails_loud("split_zip_created_by_winrar.zip", 279);
}

#[test]
fn infozip_split_archive_fails_loud() {
    assert_split_fails_loud("split_zip_created_by_zip.zip", 272);
}

// ---- Additional independent producers for the extra-field parsers ----

#[test]
fn ntfs_mtime_across_producers_matches_oracle() {
    // Same instant written by different engines; ground truth = zipdetails NTFS
    // Mtime (FILETIME ticks). WinZip truncates to 1-second (…40000), 7-Zip and
    // WinRAR keep 100 ns precision (…48179) — a real producer difference.
    for (file, want) in [
        ("ntfs-7zip.zip", 131_539_831_172_448_179_u64),
        ("ntfs-winrar.zip", 131_539_831_172_448_179),
    ] {
        let mut ar = ZipArchive::new(Cursor::new(load(file))).unwrap();
        let view = ar.structural_view().unwrap();
        assert_eq!(view[0].extra.ntfs_mtime, Some(want), "{file}");
    }
}

#[test]
fn unix_mtime_across_producers_matches_oracle() {
    let mut ar = ZipArchive::new(Cursor::new(load("unixtime-infozip.zip"))).unwrap();
    assert_eq!(
        ar.structural_view().unwrap()[0].extra.unix_mtime,
        Some(1_509_509_517),
        "unixtime-infozip.zip"
    );

    // Multi-entry Info-ZIP archive; ground truth = zipdetails UT mtime per entry.
    let mut ar = ZipArchive::new(Cursor::new(load("unixtime-infozip-multi.zip"))).unwrap();
    let got: Vec<_> = ar
        .structural_view()
        .unwrap()
        .iter()
        .map(|e| e.extra.unix_mtime)
        .collect();
    assert_eq!(
        got,
        vec![
            Some(1_323_338_664),
            Some(1_323_338_690),
            Some(1_323_338_886),
            Some(1_323_338_768),
        ]
    );
}

#[test]
fn zip64_split_archive_fails_loud() {
    // A third spanned producer: the zip64 variant of a real Info-ZIP split.
    assert_split_fails_loud("split_zip64.zip", 272);
}

#[test]
fn legacy_codecs_are_recognized_and_refused() {
    // Real archives using legacy methods (Apache Commons Compress). `unzip`
    // extracts them, confirming they are genuine Shrink/Implode streams; our
    // decoder recognizes the method by name and refuses to decode rather than
    // producing wrong bytes.
    for (file, method) in [
        ("shrunk.zip", CompressionMethod::Shrunk),
        ("imploded.zip", CompressionMethod::Imploded),
    ] {
        let mut ar = ZipArchive::new(Cursor::new(load(file))).unwrap();
        let view = ar.structural_view().unwrap();
        assert_eq!(view[0].central.method, method, "{file}: method recognized");
        assert!(
            matches!(
                ar.by_index(0),
                Err(ZipCoreError::UnsupportedMethod(m)) if m == method
            ),
            "{file}: must fail loud with the named method, not decode wrong bytes"
        );
    }
}

#[test]
fn libzip_unicode_path_and_comment_match_oracle() {
    // libzip regress corpus (BSD-3): CP437 main names with Info-ZIP Unicode
    // extras. Ground truth = zipdetails UnicodeName / UnicodeCom.
    let mut ar = ZipArchive::new(Cursor::new(load("unicode-path-libzip.zip"))).unwrap();
    assert_eq!(
        ar.structural_view().unwrap()[0]
            .extra
            .unicode_path
            .as_deref(),
        Some("ÄÖÜßäöü"),
        "0x7075 Unicode Path (libzip)"
    );

    let mut ar = ZipArchive::new(Cursor::new(load("unicode-comment-libzip.zip"))).unwrap();
    let with_comment: Vec<_> = ar
        .structural_view()
        .unwrap()
        .into_iter()
        .filter_map(|e| e.extra.unicode_comment)
        .collect();
    assert_eq!(
        with_comment,
        vec!["ÄÖÜßäöü".to_string()],
        "0x6375 Unicode Comment (libzip)"
    );
}

#[test]
fn winzip_unicode_path_and_comment_together_match_oracle() {
    // winzip-yu.zip (zipdetails corpus, Artistic-1.0/Perl) carries BOTH a
    // Unicode Path (0x7075) and a Unicode Comment (0x6375) on one entry — a
    // third 0x7075 producer and a second 0x6375 producer.
    let mut ar = ZipArchive::new(Cursor::new(load("unicode-both-winzip.zip"))).unwrap();
    let e = &ar.structural_view().unwrap()[0];
    assert_eq!(e.extra.unicode_path.as_deref(), Some("Café.txt"));
    assert_eq!(e.extra.unicode_comment.as_deref(), Some("Café"));
}

#[test]
fn ppmd_codec_is_recognized_and_refused() {
    // Real WinZip PPMd archive (method 98); recognized by name, refused.
    let mut ar = ZipArchive::new(Cursor::new(load("ppmd.zip"))).unwrap();
    assert_eq!(
        ar.structural_view().unwrap()[0].central.method,
        CompressionMethod::Ppmd
    );
    assert!(matches!(
        ar.by_index(0),
        Err(ZipCoreError::UnsupportedMethod(CompressionMethod::Ppmd))
    ));
}

// ---- SecureZIP for Mac v14.50.32: PKWARE strong encryption + CD signature ----
// Real SecureZIP output on a throwaway lorem.txt, signed with a throwaway
// self-signed cert (CN=org.radare.radare2 — no personal identity). One file
// exercises both SecureZIP-only paths. Tier-2 (real engine, our scenario).

#[test]
fn securezip_strong_encryption_is_refused() {
    let mut ar = ZipArchive::new(Cursor::new(load("securezip-strong-signed.zip"))).unwrap();
    // GP-flag bit 6 + 0x0017 strong-encryption header, AES-256, certificate-based.
    assert!(
        matches!(
            ar.by_index_decrypt(0, b"whatever"),
            Err(ZipCoreError::UnsupportedEncryption { .. })
        ),
        "PKWARE strong encryption must be refused"
    );
}

#[test]
fn securezip_central_directory_signature_is_detected() {
    let ar = ZipArchive::new(Cursor::new(load("securezip-strong-signed.zip"))).unwrap();
    // The archive carries a 0x05054b50 digital-signature record (346 bytes of
    // signature data) embedded within the EOCD's cd_size span, before the EOCD.
    assert_eq!(
        ar.summary().archive_signature_len,
        Some(346),
        "the central-directory digital signature must be recognized and its length surfaced"
    );
}
