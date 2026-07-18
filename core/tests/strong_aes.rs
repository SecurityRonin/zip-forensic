//! PKWARE SecureZIP strong encryption — password-based AES decryption.
//!
//! The in-scope case is the *password* branch of PKWARE strong encryption
//! (GP-flag bit 6) with an AES algorithm id (0x660E/0x660F/0x6610). Every other
//! strong variant — certificate-based, 3DES-ERD, non-AES — stays refused loud.
//!
//! Tier-1 ground truth: the committed `securezip-strong-aes256-pw.expected` is
//! the byte-exact output of `7zz x -so -p'Sr0ninPass!'` on the fixture (captured
//! at commit time; the env-gated `oracle_7zz_matches` test re-derives it live
//! when `7zz` is present, so the committed bytes cannot silently drift).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read};

use zip_core::{ZipArchive, ZipCoreError};

const FIXTURE: &[u8] = include_bytes!("data/securezip-strong-aes256-pw.zip");
const EXPECTED: &[u8] = include_bytes!("data/securezip-strong-aes256-pw.expected");
const SIGNED: &[u8] = include_bytes!("data/securezip-strong-signed.zip");
const PASSWORD: &[u8] = b"Sr0ninPass!";

fn decrypt(zip: &[u8], name: &str, password: &[u8]) -> Result<Vec<u8>, ZipCoreError> {
    let mut ar = ZipArchive::new(Cursor::new(zip.to_vec()))?;
    let mut f = ar.by_name_decrypt(name, password)?;
    let mut out = Vec::new();
    f.read_to_end(&mut out).map_err(|e| {
        // Surface the inner ZipCoreError (WrongPassword/CRC) that ZipFile wraps in
        // io::Error::other, so callers can match on the typed variant.
        match e
            .into_inner()
            .and_then(|b| b.downcast::<ZipCoreError>().ok())
        {
            Some(inner) => *inner,
            None => ZipCoreError::WrongPassword(name.to_string()),
        }
    })?;
    Ok(out)
}

#[test]
fn decrypts_fixture_byte_for_byte_vs_oracle() {
    let out = decrypt(FIXTURE, "secret.txt", PASSWORD).expect("must decrypt");
    assert_eq!(
        out, EXPECTED,
        "decrypted bytes must equal the 7zz -so ground truth"
    );
}

#[test]
fn wrong_password_refuses_loud() {
    let err = decrypt(FIXTURE, "secret.txt", b"WrongPass!").unwrap_err();
    assert!(
        matches!(err, ZipCoreError::WrongPassword(_)),
        "a wrong password must fail loud (WrongPassword), got {err:?}"
    );
}

#[test]
fn certificate_variant_stays_refused() {
    // securezip-strong-signed.zip uses the *certificate* strong variant — with no
    // private key it must stay refused loud, never mis-decoded.
    let mut ar = ZipArchive::new(Cursor::new(SIGNED.to_vec())).unwrap();
    let name = ar.file_names().next().unwrap().to_string();
    let res = ar.by_name_decrypt(&name, PASSWORD).map(|_| ());
    assert!(
        matches!(res, Err(ZipCoreError::UnsupportedEncryption { .. })),
        "certificate strong encryption must stay refused, got {res:?}"
    );
}

/// Tier-1 differential: when `7zz` is available, prove the committed `.expected`
/// bytes really are 7-Zip's output (closes the loop so the oracle file can't be
/// fudged). Skips cleanly when the tool is absent — the committed-bytes gate
/// above does not depend on it.
#[test]
fn oracle_7zz_matches_expected() {
    use std::process::Command;
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = format!("{manifest}/tests/data/securezip-strong-aes256-pw.zip");
    let out = match Command::new("7zz")
        .args(["x", "-so", "-p", "Sr0ninPass!", &path])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            eprintln!("skipping: 7zz not available");
            return;
        }
    };
    assert_eq!(
        out, EXPECTED,
        "committed .expected must equal live 7zz output"
    );
}
