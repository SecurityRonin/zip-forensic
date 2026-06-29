//! Malformed/edge container inputs driving the parser's error branches
//! (Paranoid Gatekeeper): every one must error cleanly, never panic. Covers the
//! bad-signature, out-of-range, too-many-entries, zip64-locator/record, zip64
//! extra-field, CP437-name, and directory-entry paths.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::{CompressionMethod, FormatError, ZipArchive, ZipCoreError};

/// Build a single-entry zip with fine-grained control over the CD copy (so its
/// fields can disagree with the LFH or carry zip64 sentinels + extra fields).
#[allow(clippy::too_many_arguments)]
fn one_entry(
    method: u16,
    name: &[u8],
    flags: u16,
    comp: &[u8],
    cd_csize: u32,
    cd_usize: u32,
    cd_lfh_offset: u32,
    cd_extra: &[u8],
) -> Vec<u8> {
    let mut o = Vec::new();
    // Local file header (real sizes, no extra).
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&flags.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(name);
    o.extend_from_slice(comp);
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&flags.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&cd_csize.to_le_bytes());
    o.extend_from_slice(&cd_usize.to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&cd_lfh_offset.to_le_bytes());
    o.extend_from_slice(name);
    o.extend_from_slice(cd_extra);
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

fn open(bytes: Vec<u8>) -> Result<ZipArchive<Cursor<Vec<u8>>>, ZipCoreError> {
    ZipArchive::new(Cursor::new(bytes))
}

#[test]
fn directory_entry_and_accessors() {
    let mut ar = open(one_entry(0, b"sub/", 0, b"", 0, 0, 0, &[])).unwrap();
    let e = ar.by_index(0).unwrap();
    assert!(e.is_dir());
    assert_eq!(e.crc32(), 0);
    assert_eq!(e.compressed_size(), 0);
}

#[test]
fn cp437_name_decoded_when_no_utf8_flag() {
    // 0xE1 is CP437 'ß'; flags bit 11 clear -> CP437 path.
    let ar = open(one_entry(0, &[0xE1, b'.', b'b'], 0, b"", 0, 0, 0, &[])).unwrap();
    assert!(ar.file_names().next().unwrap().starts_with('ß'));
}

#[test]
fn lfh_bad_signature_errors() {
    let mut bytes = one_entry(0, b"f", 0, b"x", 1, 1, 0, &[]);
    bytes[0] = 0x00; // corrupt the LFH signature
    let mut ar = open(bytes).unwrap(); // CD still parses
    assert!(matches!(
        ar.by_index(0).map(|_| ()),
        Err(ZipCoreError::Format(FormatError::BadSignature { .. }))
    ));
}

#[test]
fn central_directory_out_of_range_errors() {
    let mut bytes = one_entry(0, b"f", 0, b"x", 1, 1, 0, &[]);
    // Patch the EOCD cd_offset (last 6 bytes: cd_offset(4) + comment_len(2)).
    let n = bytes.len();
    bytes[n - 6..n - 2].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    assert!(matches!(
        open(bytes).map(|_| ()),
        Err(ZipCoreError::Format(
            FormatError::CentralDirOutOfRange { .. }
        ))
    ));
}

#[test]
fn central_dir_header_bad_signature_errors() {
    let bytes = one_entry(0, b"f", 0, b"x", 1, 1, 0, &[]);
    let mut b = bytes.clone();
    // The CD header is right after LFH+data; find PK\x01\x02 and corrupt it.
    let cd = b
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    b[cd + 1] = 0x00;
    assert!(open(b).is_err());
}

#[test]
fn truncated_central_directory_errors() {
    let mut bytes = one_entry(0, b"f", 0, b"x", 1, 1, 0, &[]);
    // Claim 2 entries in the EOCD while only one CD header exists.
    let n = bytes.len();
    // EOCD layout from end: ...total_entries(2) at n-12..n-10.
    bytes[n - 12..n - 10].copy_from_slice(&2u16.to_le_bytes());
    bytes[n - 14..n - 12].copy_from_slice(&2u16.to_le_bytes()); // entries-this-disk
    assert!(open(bytes).is_err());
}

#[test]
fn zip64_locator_too_close_to_start() {
    // A bare 22-byte EOCD with a sentinel offset: no room for a zip64 locator.
    let mut eocd = Vec::new();
    eocd.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    eocd.extend_from_slice(&[0u8; 12]);
    eocd.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // cd_offset sentinel
    eocd.extend_from_slice(&0u16.to_le_bytes());
    assert!(matches!(
        open(eocd).map(|_| ()),
        Err(ZipCoreError::Format(FormatError::Zip64Unsupported))
    ));
}

#[test]
fn zip64_locator_bad_signature() {
    // 20 bytes of junk (wrong locator sig) before a sentinel EOCD.
    let mut b = vec![0u8; 20];
    b.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    assert!(open(b).is_err());
}

#[test]
fn zip64_eocd_record_bad_signature() {
    // Valid locator pointing at offset 0, but offset 0 is not a zip64 EOCD record.
    let mut b = vec![0u8; 8]; // junk where the zip64 EOCD record should be
    let loc_off = b.len();
    b.extend_from_slice(&[0x50, 0x4b, 0x06, 0x07]); // locator sig
    b.extend_from_slice(&0u32.to_le_bytes()); // disk
    b.extend_from_slice(&0u64.to_le_bytes()); // points at offset 0 (junk)
    b.extend_from_slice(&1u32.to_le_bytes()); // total disks
    let _ = loc_off;
    b.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    assert!(open(b).is_err());
}

// ---- zip64 central-directory extra-field branches ----

fn z64_extra(records: &[(u16, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (id, data) in records {
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
    }
    v
}

#[test]
fn zip64_extra_resolves_compressed_and_offset() {
    // All three base fields sentinel; the extra carries usize, csize, offset (8 each).
    let payload = b"hello";
    let mut body = Vec::new();
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // lfh offset = 0
    let extra = z64_extra(&[(0x0001, &body)]);
    let bytes = one_entry(
        0,
        b"f",
        0,
        payload,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        &extra,
    );
    let mut ar = open(bytes).unwrap();
    let e = ar.by_name("f").unwrap();
    // All three sentinels resolved from the zip64 extra field.
    assert_eq!(e.compressed_size(), payload.len() as u64);
    assert_eq!(e.size(), payload.len() as u64);
}

#[test]
fn zip64_extra_skips_unrelated_record() {
    // A non-zip64 extra record precedes the zip64 one -> exercises the skip path.
    let mut body = Vec::new();
    body.extend_from_slice(&5u64.to_le_bytes()); // uncompressed size
    let extra = z64_extra(&[(0x9999, &[1, 2, 3, 4]), (0x0001, &body)]);
    let bytes = one_entry(0, b"f", 0, b"hello", 5, 0xFFFF_FFFF, 0, &extra);
    let mut ar = open(bytes).unwrap();
    assert_eq!(ar.by_name("f").unwrap().size(), 5);
}

#[test]
fn zip64_sentinel_without_extra_is_inconsistent() {
    let extra = z64_extra(&[(0x9999, &[0, 0])]); // no id-0x0001 record
    let bytes = one_entry(0, b"f", 0, b"hello", 5, 0xFFFF_FFFF, 0, &extra);
    assert!(matches!(
        open(bytes).map(|_| ()),
        Err(ZipCoreError::Format(FormatError::Zip64Inconsistent))
    ));
}

#[test]
fn unsupported_method_value_is_preserved() {
    let mut ar = open(one_entry(99, b"f", 0, b"x", 1, 1, 0, &[])).unwrap();
    assert!(matches!(
        ar.by_index(0).map(|_| ()),
        Err(ZipCoreError::UnsupportedMethod(CompressionMethod::Unknown(
            99
        )))
    ));
}

/// Build a zip64-promoted archive: 32-bit EOCD sentinels + a Zip64 EOCD record
/// (with a chosen total-entries) + locator. `pre` pads the front so the record
/// offset is non-trivial.
fn zip64_archive(total_entries: u64, record_sig_ok: bool) -> Vec<u8> {
    let mut b = Vec::new();
    let rec_off = b.len() as u64;
    b.extend_from_slice(if record_sig_ok {
        &[0x50, 0x4b, 0x06, 0x06]
    } else {
        &[0x00, 0x00, 0x00, 0x00]
    });
    b.extend_from_slice(&44u64.to_le_bytes()); // record size
    b.extend_from_slice(&45u16.to_le_bytes());
    b.extend_from_slice(&45u16.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // disk
    b.extend_from_slice(&0u32.to_le_bytes()); // cd disk
    b.extend_from_slice(&total_entries.to_le_bytes()); // entries this disk
    b.extend_from_slice(&total_entries.to_le_bytes()); // total
    b.extend_from_slice(&0u64.to_le_bytes()); // cd size
    b.extend_from_slice(&0u64.to_le_bytes()); // cd offset
    b.extend_from_slice(&[0x50, 0x4b, 0x06, 0x07]); // locator
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&rec_off.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    b.extend_from_slice(&0u16.to_le_bytes()); // disk
    b.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // entries this disk (sentinel)
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // total entries (sentinel)
    b.extend_from_slice(&0u32.to_le_bytes()); // cd size
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // cd offset (sentinel)
    b.extend_from_slice(&0u16.to_le_bytes()); // comment len
    b
}

#[test]
fn zip64_too_many_entries_rejected() {
    assert!(matches!(
        open(zip64_archive(20_000_000, true)).map(|_| ()),
        Err(ZipCoreError::Format(FormatError::TooManyEntries(_)))
    ));
}

#[test]
fn zip64_eocd_record_wrong_signature_rejected() {
    assert!(open(zip64_archive(1, false)).is_err());
}

#[test]
fn enclosed_name_rejects_nul_and_dot_only() {
    let mut ar = open(one_entry(0, b"a\x00b", 0, b"", 0, 0, 0, &[])).unwrap();
    assert_eq!(ar.by_index(0).unwrap().enclosed_name(), None); // NUL
    let mut ar = open(one_entry(0, b".", 0, b"", 0, 0, 0, &[])).unwrap();
    assert_eq!(ar.by_index(0).unwrap().enclosed_name(), None); // resolves empty
}
