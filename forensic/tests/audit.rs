//! zip-forensic audit tests: the pure `audit_layout` over constructed structural
//! views, plus an end-to-end `audit_reader` against a hand-built archive whose
//! local file header is byte-edited to disagree with the central directory (the
//! headline CD!=LFH tamper signal).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use forensicnomicon::report::{Category, Observation, Severity};
use zip_core::{ArchiveSummary, CompressionMethod, EntryLayout, ExtraFields, HeaderFields};
use zip_forensic::{audit_container, audit_layout, audit_reader, AnomalyKind};

fn hf(name: &str) -> HeaderFields {
    HeaderFields {
        name: name.to_string(),
        method: CompressionMethod::Stored,
        flags: 0,
        crc32: 0x1234_5678,
        compressed_size: 10,
        uncompressed_size: 10,
    }
}

fn layout(central: HeaderFields, local: HeaderFields) -> Vec<EntryLayout> {
    vec![EntryLayout {
        index: 0,
        lfh_offset: 0,
        data_start: 100,
        central,
        local,
        extra: ExtraFields::default(),
    }]
}

fn codes(a: &[zip_forensic::Anomaly]) -> Vec<&str> {
    a.iter().map(|x| x.code).collect()
}

#[test]
fn flags_crc_mismatch_between_cd_and_lfh() {
    let mut local = hf("a.bin");
    local.crc32 = 0xDEAD_BEEF; // disagrees with the CD copy
    let found = audit_layout(&layout(hf("a.bin"), local));
    assert_eq!(codes(&found), ["ZIP-CD-LFH-MISMATCH"]);
    assert_eq!(found[0].severity, Severity::High);
    assert_eq!(found[0].category(), Category::Integrity);
}

#[test]
fn no_mismatch_when_data_descriptor_zeroes_the_lfh() {
    // GP flag bit 3 => LFH crc/sizes are legitimately zero (live in the descriptor).
    let mut local = hf("a.bin");
    local.flags = 0x0008;
    local.crc32 = 0;
    local.compressed_size = 0;
    local.uncompressed_size = 0;
    let found = audit_layout(&layout(hf("a.bin"), local));
    assert!(
        found.is_empty(),
        "data descriptor must not be flagged: {found:?}"
    );
}

#[test]
fn no_size_mismatch_on_zip64_sentinel_in_lfh() {
    let mut local = hf("a.bin");
    local.compressed_size = 0xFFFF_FFFF; // zip64 sentinel, real value in extra field
    local.uncompressed_size = 0xFFFF_FFFF;
    let found = audit_layout(&layout(hf("a.bin"), local));
    assert!(
        found.is_empty(),
        "zip64 sentinel must not be flagged: {found:?}"
    );
}

#[test]
fn detects_traversal_and_absolute_names() {
    let trav = audit_layout(&layout(hf("../../etc/passwd"), hf("../../etc/passwd")));
    assert!(codes(&trav).contains(&"ZIP-NAME-TRAVERSAL"));

    let abs = audit_layout(&layout(hf("/etc/shadow"), hf("/etc/shadow")));
    assert!(codes(&abs).contains(&"ZIP-NAME-ABSOLUTE"));

    let drive = audit_layout(&layout(hf("C:\\Windows\\x"), hf("C:\\Windows\\x")));
    assert!(codes(&drive).contains(&"ZIP-NAME-ABSOLUTE"));
}

#[test]
fn detects_prepended_data() {
    let mut l = layout(hf("a.bin"), hf("a.bin"));
    l[0].lfh_offset = 4096; // first member not at offset 0 => 4096 prepended bytes
    let found = audit_layout(&l);
    assert!(codes(&found).contains(&"ZIP-PREPENDED-DATA"));
    let pre = found
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::PrependedData { .. }))
        .unwrap();
    assert_eq!(pre.severity, Severity::Low);
}

#[test]
fn clean_archive_has_no_anomalies() {
    let found = audit_layout(&layout(hf("dir/file.txt"), hf("dir/file.txt")));
    assert!(found.is_empty(), "clean entry flagged: {found:?}");
}

// ---- remaining structural audits (HANDOFF section 3) ----

fn two_entry_layout(
    a: HeaderFields,
    a_start: u64,
    b: HeaderFields,
    b_start: u64,
) -> Vec<EntryLayout> {
    vec![
        EntryLayout {
            index: 0,
            lfh_offset: 0,
            data_start: a_start,
            central: a.clone(),
            local: a,
            extra: ExtraFields::default(),
        },
        EntryLayout {
            index: 1,
            lfh_offset: 200,
            data_start: b_start,
            central: b.clone(),
            local: b,
            extra: ExtraFields::default(),
        },
    ]
}

#[test]
fn detects_overlapping_member_data() {
    // entry0 occupies [100, 150); entry1 starts at 120 -> their data ranges overlap.
    let mut a = hf("a.bin");
    a.compressed_size = 50;
    let mut b = hf("b.bin");
    b.compressed_size = 50;
    let found = audit_layout(&two_entry_layout(a, 100, b, 120));
    assert!(codes(&found).contains(&"ZIP-OVERLAP"), "got {found:?}");
}

#[test]
fn detects_bidi_override_in_name() {
    // U+202E RIGHT-TO-LEFG OVERRIDE — the classic "gpj.exe" spoof.
    let name = "invoice\u{202e}fdp.exe";
    let found = audit_layout(&layout(hf(name), hf(name)));
    assert!(codes(&found).contains(&"ZIP-NAME-BIDI"), "got {found:?}");
}

#[test]
fn detects_control_chars_in_name() {
    let name = "evil\u{0007}\u{0000}.txt";
    let found = audit_layout(&layout(hf(name), hf(name)));
    assert!(codes(&found).contains(&"ZIP-NAME-CONTROL"), "got {found:?}");
}

fn summary(file_len: u64, eocd_end: u64, disk: u32, cd_disk: u32) -> ArchiveSummary {
    ArchiveSummary {
        file_len,
        central_dir_offset: 0,
        central_dir_size: 0,
        eocd_end_offset: eocd_end,
        comment_len: 0,
        disk_number: disk,
        cd_start_disk: cd_disk,
        archive_signature_len: None,
    }
}

#[test]
fn detects_trailing_data_after_eocd() {
    let s = summary(5000, 4000, 0, 0); // 1000 bytes past the EOCD
    let found = audit_container(&s, &[]);
    assert!(
        codes(&found).contains(&"ZIP-TRAILING-DATA"),
        "got {found:?}"
    );
    // No trailing data when the file ends exactly at the EOCD.
    assert!(audit_container(&summary(4000, 4000, 0, 0), &[]).is_empty());
}

#[test]
fn detects_spanning_disk_numbers() {
    let found = audit_container(&summary(100, 100, 1, 0), &[]);
    assert!(
        codes(&found).contains(&"ZIP-SPANNING-ANOMALY"),
        "got {found:?}"
    );
    // Sentinel disk numbers (zip64) are NOT a spanning anomaly.
    assert!(audit_container(&summary(100, 100, 0xFFFF_FFFF, 0xFFFF_FFFF), &[]).is_empty());
}

// ---- end-to-end via audit_reader + the zip-core structural_view seam ----

/// Minimal single-entry STORED zip; returns (bytes, absolute offset of the LFH
/// CRC field) so a test can corrupt the local copy.
fn stored_zip(name: &str, payload: &[u8]) -> (Vec<u8>, usize) {
    let crc = crc32(payload);
    let nb = name.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let lfh_crc_off = out.len(); // CRC field starts here
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(nb);
    out.extend_from_slice(payload);
    let cd = out.len();
    out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(nb);
    let cd_size = out.len() - cd;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    (out, lfh_crc_off)
}

fn crc32(data: &[u8]) -> u32 {
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

#[test]
fn end_to_end_clean_zip_is_silent() {
    let (bytes, _) = stored_zip("doc.txt", b"hello world");
    let found = audit_reader(Cursor::new(bytes)).unwrap();
    assert!(found.is_empty(), "clean archive flagged: {found:?}");
}

#[test]
fn end_to_end_tampered_lfh_crc_is_flagged() {
    let (mut bytes, crc_off) = stored_zip("doc.txt", b"hello world");
    bytes[crc_off] ^= 0xFF; // corrupt only the LOCAL header CRC; CD copy unchanged
    let found = audit_reader(Cursor::new(bytes)).unwrap();
    assert!(
        found.iter().any(|a| a.code == "ZIP-CD-LFH-MISMATCH"
            && matches!(&a.kind, AnomalyKind::CdLfhMismatch { field: "crc32", .. })),
        "expected a crc32 CD/LFH mismatch, got {found:?}"
    );
}

#[test]
fn end_to_end_corrupt_payload_is_a_crc_mismatch() {
    let payload = b"the quick brown fox";
    let (mut bytes, _) = stored_zip("doc.txt", payload);
    // Flip a byte INSIDE the stored payload (CD/LFH CRC fields untouched), so the
    // decoded data's CRC no longer matches the recorded value.
    let pos = bytes
        .windows(payload.len())
        .position(|w| w == &payload[..])
        .expect("payload present verbatim");
    bytes[pos + 3] ^= 0xFF;
    let found = audit_reader(Cursor::new(bytes)).unwrap();
    assert!(
        found.iter().any(|a| a.code == "ZIP-CRC-MISMATCH"),
        "expected ZIP-CRC-MISMATCH, got {found:?}"
    );
}
