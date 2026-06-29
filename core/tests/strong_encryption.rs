//! PKWARE Strong Encryption (GP flag bit 6) and masked/central-directory
//! encryption (bit 13) are not supported — they must fail loud with
//! UnsupportedEncryption rather than be mishandled as ZipCrypto.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::Cursor;

use zip_core::{ZipArchive, ZipCoreError};

/// Minimal single-entry zip with explicit GP flags (Stored method, tiny data).
fn zip_with_flags(flags: u16) -> Vec<u8> {
    let name = b"f";
    let data = b"ciphertext-ish";
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&flags.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes()); // method = Stored
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
    o.extend_from_slice(&flags.to_le_bytes());
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
fn strong_encryption_bit6_fails_loud() {
    // bit 0 (encrypted) + bit 6 (strong encryption).
    let bytes = zip_with_flags(0x0001 | 0x0040);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(
        matches!(
            ar.by_name_decrypt("f", b"pw"),
            Err(ZipCoreError::UnsupportedEncryption { .. })
        ),
        "strong encryption must not be mishandled as ZipCrypto"
    );
}

#[test]
fn masked_central_directory_bit13_fails_loud() {
    // bit 0 (encrypted) + bit 13 (masked header values / CD encryption).
    let bytes = zip_with_flags(0x0001 | 0x2000);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        ar.by_name_decrypt("f", b"pw"),
        Err(ZipCoreError::UnsupportedEncryption { .. })
    ));
}
