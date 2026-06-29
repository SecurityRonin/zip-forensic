//! Exhaustive coverage of every `AnomalyKind`'s note/evidence/severity/code/
//! category arms and the `Observation` -> `Finding` conversion, plus `audit_path`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use forensicnomicon::report::{Observation, Source};
use zip_core::{CompressionMethod, EntryLayout, HeaderFields};
use zip_forensic::{audit_layout, Anomaly, AnomalyKind};

fn hdr(name: &str, method: CompressionMethod, crc: u32, csize: u64, usize_: u64) -> HeaderFields {
    HeaderFields {
        name: name.to_string(),
        method,
        flags: 0,
        crc32: crc,
        compressed_size: csize,
        uncompressed_size: usize_,
    }
}

#[test]
fn cd_lfh_name_method_and_size_mismatches() {
    // central vs local disagree on name, method, and both sizes simultaneously.
    let central = hdr("real.bin", CompressionMethod::Stored, 1, 10, 10);
    let local = hdr("fake.bin", CompressionMethod::Deflated, 1, 20, 30);
    let layout = vec![EntryLayout {
        index: 0,
        lfh_offset: 0,
        data_start: 100,
        central,
        local,
    }];
    let fields: Vec<_> = audit_layout(&layout)
        .into_iter()
        .filter_map(|a| match a.kind {
            AnomalyKind::CdLfhMismatch { field, .. } => Some(field),
            _ => None,
        })
        .collect();
    for f in ["name", "method", "compressed_size", "uncompressed_size"] {
        assert!(fields.contains(&f), "missing {f} mismatch in {fields:?}");
    }
}

#[test]
fn bidi_isolates_and_marks_are_detected() {
    for name in ["a\u{2066}b", "a\u{200e}b", "a\u{2069}b"] {
        let l = vec![EntryLayout {
            index: 0,
            lfh_offset: 0,
            data_start: 0,
            central: hdr(name, CompressionMethod::Stored, 0, 0, 0),
            local: hdr(name, CompressionMethod::Stored, 0, 0, 0),
        }];
        assert!(
            audit_layout(&l).iter().any(|a| a.code == "ZIP-NAME-BIDI"),
            "bidi not detected for {name:?}"
        );
    }
}

fn all_kinds() -> Vec<AnomalyKind> {
    vec![
        AnomalyKind::CdLfhMismatch {
            index: 1,
            name: "a".into(),
            field: "crc32",
            central: "0x1".into(),
            local: "0x2".into(),
        },
        AnomalyKind::NameTraversal {
            index: 0,
            name: "../x".into(),
        },
        AnomalyKind::NameAbsolute {
            index: 0,
            name: "/x".into(),
        },
        AnomalyKind::PrependedData { length: 10 },
        AnomalyKind::TrailingData { length: 20 },
        AnomalyKind::Overlap {
            index_a: 0,
            index_b: 1,
            at: 100,
        },
        AnomalyKind::SpanningAnomaly {
            disk_number: 1,
            cd_start_disk: 2,
        },
        AnomalyKind::NameBidi {
            index: 0,
            name: "x\u{202e}y".into(),
        },
        AnomalyKind::NameControl {
            index: 0,
            name: "x\u{7}".into(),
        },
        AnomalyKind::CrcMismatch {
            index: 3,
            name: "z".into(),
        },
    ]
}

#[test]
fn every_kind_produces_note_evidence_and_finding() {
    let source = Source {
        analyzer: "zip-forensic".into(),
        scope: String::new(),
        version: None,
    };
    for kind in all_kinds() {
        // Exercises severity/code/note via Anomaly::new, then category/evidence.
        let anomaly = Anomaly::new(kind.clone());
        assert!(!anomaly.note.is_empty());
        assert!(anomaly.code.starts_with("ZIP-"));
        let _ = anomaly.severity();
        let _ = anomaly.code();
        let _ = anomaly.note();
        let _ = anomaly.category();
        assert!(!anomaly.evidence().is_empty());
        // The producer conversion to a forensicnomicon Finding.
        let finding = anomaly.to_finding(source.clone());
        assert_eq!(finding.code, kind.code());
    }
}

#[test]
fn audit_path_reads_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.zip");
    // A clean single-entry stored zip (built inline) audits with no anomalies.
    let bytes = clean_stored_zip();
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    let found = zip_forensic::audit_path(&path).unwrap();
    assert!(found.is_empty(), "clean archive flagged: {found:?}");

    // Missing file surfaces as an error, not a panic.
    assert!(zip_forensic::audit_path(dir.path().join("nope.zip").as_path()).is_err());
}

fn clean_stored_zip() -> Vec<u8> {
    let payload = b"hi";
    let crc = {
        let mut c = 0xFFFF_FFFFu32;
        for &b in payload {
            c ^= u32::from(b);
            for _ in 0..8 {
                let m = (c & 1).wrapping_neg();
                c = (c >> 1) ^ (0xEDB8_8320 & m);
            }
        }
        !c
    };
    let nb = b"f.bin";
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&crc.to_le_bytes());
    o.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    o.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    o.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(nb);
    o.extend_from_slice(payload);
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&crc.to_le_bytes());
    o.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    o.extend_from_slice(&(payload.len() as u32).to_le_bytes());
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
