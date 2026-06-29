//! Decryption tests: traditional ZipCrypto and WinZip AES (method 99).
//!
//! Committed fixtures (7z, known password `Infected123`, known payload) validate
//! both methods in CI without the malware corpus. An env-gated test additionally
//! decrypts a REAL ZipCrypto malware sample (objective-see XLoader, password
//! `infected`) and cross-checks against the zip-rs oracle — bytes are only
//! compared, never executed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::io::{Cursor, Read};
use std::path::PathBuf;

use zip_core::ZipArchive;

const PW: &[u8] = b"Infected123";

fn payload() -> Vec<u8> {
    (0..20_000u32).map(|i| (i / 64) as u8).collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/data/encrypted"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn zip_core_decrypt(bytes: &[u8], name: &str, pw: &[u8]) -> Vec<u8> {
    let mut ar = ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut e = ar.by_name_decrypt(name, pw).unwrap();
    let mut out = Vec::new();
    e.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn zipcrypto_decrypts_to_payload() {
    assert_eq!(
        zip_core_decrypt(&fixture("zipcrypto.zip"), "file.bin", PW),
        payload()
    );
}

#[test]
fn aes256_decrypts_to_payload() {
    assert_eq!(
        zip_core_decrypt(&fixture("aes256.zip"), "file.bin", PW),
        payload()
    );
}

#[test]
fn encrypted_entry_without_password_errors() {
    // Secure-by-default: a plain by_name on an encrypted entry must refuse, not
    // return ciphertext or garbage.
    let mut ar = ZipArchive::new(Cursor::new(fixture("zipcrypto.zip"))).unwrap();
    assert!(ar.by_name("file.bin").is_err());
    let mut ar = ZipArchive::new(Cursor::new(fixture("aes256.zip"))).unwrap();
    assert!(ar.by_name("file.bin").is_err());
}

#[test]
fn wrong_password_errors() {
    let mut ar = ZipArchive::new(Cursor::new(fixture("zipcrypto.zip"))).unwrap();
    assert!(ar.by_name_decrypt("file.bin", b"wrong-password").is_err());
    let mut ar = ZipArchive::new(Cursor::new(fixture("aes256.zip"))).unwrap();
    assert!(ar.by_name_decrypt("file.bin", b"wrong-password").is_err());
}

/// Real-world ZipCrypto: the objective-see XLoader malware sample. Env-gated
/// (`ZIP_CORE_ZIPCRYPTO_ZIP`). Decrypts a small encrypted entry and asserts it
/// equals the zip-rs oracle's decryption — bytes compared, never executed.
#[test]
fn zipcrypto_real_xloader_matches_oracle() {
    let Ok(path) = std::env::var("ZIP_CORE_ZIPCRYPTO_ZIP") else {
        eprintln!("skipping: ZIP_CORE_ZIPCRYPTO_ZIP not set");
        return;
    };
    let pw = b"infected";
    let entry = "XLoader/Statement SKBMT 09818/resources/NVFFY";
    let bytes = std::fs::read(&path).unwrap();

    let got = zip_core_decrypt(&bytes, entry, pw);

    let mut oar = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut oe = oar.by_name_decrypt(entry, pw).unwrap();
    let mut want = Vec::new();
    oe.read_to_end(&mut want).unwrap();

    assert_eq!(got, want, "zip-core ZipCrypto decrypt vs zip-rs oracle");
}
