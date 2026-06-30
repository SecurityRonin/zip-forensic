//! Tier-1 validation of the anomaly analyzer against real third-party archives.
//!
//! These complement the synthetic `audit.rs` tests (which prove each rule FIRES
//! on crafted bad input — tier-3, since attack signatures like overlap, bidi
//! names, CD/LFH and CRC mismatch do not occur in benign real corpora). Here we
//! check the analyzer against *real* artifacts. SPECIFICITY: well-formed real
//! zips produce no anomalies (no false positives). SENSITIVITY: a real libzip
//! file that genuinely contains control-character entry names is flagged
//! NAME-CONTROL. Ground truth is the structural fact of each file, not a
//! self-authored answer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/tests/data"))
}

fn audit(name: &str) -> Vec<zip_forensic::Anomaly> {
    let bytes = std::fs::read(corpus_dir().join(name)).unwrap();
    zip_forensic::audit_reader(Cursor::new(bytes)).unwrap()
}

#[test]
fn no_false_positive_anomalies_on_benign_real_archives() {
    // Every committed real third-party zip that is a complete, well-formed
    // single-volume archive must produce ZERO anomalies. Exclusions:
    //  - `split_*`: last segment only -> data on other disks, not auditable.
    //  - `unicode-comment-libzip.zip`: genuinely has control-char names (see
    //    the sensitivity test below) -> a true positive, not a false one.
    let mut checked = 0;
    for entry in std::fs::read_dir(corpus_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|x| x != "zip") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("split_") || name == "unicode-comment-libzip.zip" {
            continue;
        }
        let anoms = audit(&name);
        let codes: Vec<_> = anoms.iter().map(|a| a.kind.code()).collect();
        assert!(
            anoms.is_empty(),
            "benign real archive {name} unexpectedly flagged: {codes:?}"
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "expected to check a meaningful corpus, got {checked}"
    );
}

#[test]
fn name_control_detected_in_real_libzip_archive() {
    // libzip `test-cp437-comment-utf-8.zip` has entries whose names contain
    // control bytes 0x01..=0x10 (a charset sweep). The analyzer must flag them.
    let anoms = audit("unicode-comment-libzip.zip");
    let n = anoms
        .iter()
        .filter(|a| a.kind.code() == "ZIP-NAME-CONTROL")
        .count();
    assert_eq!(
        n, 3,
        "expected NAME-CONTROL on the 3 control-char-named entries"
    );
}
