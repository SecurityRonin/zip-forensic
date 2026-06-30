//! The central-directory digital-signature record (header 0x05054b50) sits after
//! the central directory. We don't verify it, but we recognize it and surface its
//! presence/length for the forensic analyzer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::ZipArchive;

/// Single-entry zip, optionally followed by a CD digital-signature record before
/// the EOCD.
fn zip_with_signature(sig_data: Option<&[u8]>) -> Vec<u8> {
    let name = b"f";
    let data = b"hi";
    let mut o = Vec::new();
    // LFH + data
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(name);
    o.extend_from_slice(data);
    // Central directory (one header)
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(name);
    let cd_size = o.len() - cd;
    // Optional CD digital-signature record (between CD and EOCD).
    if let Some(sig) = sig_data {
        o.extend_from_slice(&[0x50, 0x4b, 0x05, 0x05]);
        o.extend_from_slice(&(sig.len() as u16).to_le_bytes());
        o.extend_from_slice(sig);
    }
    // EOCD (cd_offset/size cover only the CD, not the signature record)
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

#[test]
fn detects_central_directory_signature_record() {
    let signed = zip_with_signature(Some(b"\x30\x82pretend-PKCS7-signature"));
    let ar = ZipArchive::new(Cursor::new(signed)).unwrap();
    assert_eq!(
        ar.summary().archive_signature_len,
        Some(b"\x30\x82pretend-PKCS7-signature".len() as u16),
        "signed archive should report its signature length"
    );
    // The entry still parses/reads normally.
    assert_eq!(ar.len(), 1);
}

#[test]
fn unsigned_archive_reports_no_signature() {
    let ar = ZipArchive::new(Cursor::new(zip_with_signature(None))).unwrap();
    assert_eq!(ar.summary().archive_signature_len, None);
}

#[test]
fn non_signature_trailing_bytes_in_cd_span_report_none() {
    // Some malformed/padded archives leave bytes between the last CD header and
    // the EOCD that are counted in cd_size but are NOT a 0x05054b50 record. These
    // must not be mistaken for a signature.
    let name = b"f";
    let data = b"hi";
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(name);
    o.extend_from_slice(data);
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(data.len() as u32).to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(name);
    // Four junk bytes after the header, counted in cd_size but not a signature.
    let junk = *b"junk";
    o.extend_from_slice(&junk);
    let cd_size = o.len() - cd; // includes the junk
    o.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&(cd_size as u32).to_le_bytes());
    o.extend_from_slice(&(cd as u32).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());

    let ar = ZipArchive::new(Cursor::new(o)).unwrap();
    assert_eq!(ar.summary().archive_signature_len, None);
}
