//! zip4n6 dispatch tests: `list` enumerates entries, `audit` reports findings,
//! and bad invocations surface a usage error (never a panic).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use zip_forensic_cli::dispatch;

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            let m = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xEDB8_8320 & m);
        }
    }
    !c
}

/// Minimal single-entry STORED zip; returns (bytes, LFH crc field offset).
fn stored_zip(name: &str, payload: &[u8]) -> (Vec<u8>, usize) {
    let crc = crc32(payload);
    let nb = name.as_bytes();
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    let crc_off = o.len();
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
    (o, crc_off)
}

fn write_tmp(bytes: &[u8]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
    (dir, path.to_string_lossy().into_owned())
}

fn run(args: &[&str]) -> Result<String, zip_forensic_cli::CliError> {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let mut out = Vec::new();
    dispatch(&argv, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

#[test]
fn list_enumerates_entries() {
    let (bytes, _) = stored_zip("dir/report.bin", b"hello world");
    let (_d, path) = write_tmp(&bytes);
    let out = run(&["zip4n6", "list", &path]).unwrap();
    assert!(out.contains("dir/report.bin"), "list output: {out}");
    assert!(out.contains("11"), "should show the 11-byte size: {out}");
}

#[test]
fn audit_reports_tampered_entry() {
    let (mut bytes, crc_off) = stored_zip("doc.txt", b"hello world");
    bytes[crc_off] ^= 0xFF; // LFH crc disagrees with the CD
    let (_d, path) = write_tmp(&bytes);
    let out = run(&["zip4n6", "audit", &path]).unwrap();
    assert!(out.contains("ZIP-CD-LFH-MISMATCH"), "audit output: {out}");
}

#[test]
fn audit_clean_archive_says_so() {
    let (bytes, _) = stored_zip("clean.txt", b"ok");
    let (_d, path) = write_tmp(&bytes);
    let out = run(&["zip4n6", "audit", &path]).unwrap();
    assert!(
        out.to_lowercase().contains("no anomalies"),
        "audit output: {out}"
    );
}

#[test]
fn no_subcommand_is_usage_error() {
    assert!(run(&["zip4n6"]).is_err());
    assert!(run(&["zip4n6", "bogus", "x"]).is_err());
    assert!(run(&["zip4n6", "list"]).is_err()); // missing path
}

#[test]
fn missing_file_is_io_error_and_displays() {
    let err = run(&["zip4n6", "list", "/no/such/zip-file.zip"]).unwrap_err();
    assert!(matches!(err, zip_forensic_cli::CliError::Io(_)));
    assert!(format!("{err}").contains("I/O error"));
}

#[test]
fn garbage_file_is_zip_error_and_displays() {
    let (_d, path) = write_tmp(b"not a zip at all, just bytes");
    let err = run(&["zip4n6", "audit", &path]).unwrap_err();
    assert!(matches!(err, zip_forensic_cli::CliError::Zip(_)));
    assert!(format!("{err}").contains("zip error"));
}

#[test]
fn usage_error_displays_usage_text() {
    let err = run(&["zip4n6"]).unwrap_err();
    assert!(format!("{err}").contains("usage: zip4n6"));
}

// ---- exercise the actual binary shell (main.rs) ----

#[test]
fn binary_runs_list() {
    let (bytes, _) = stored_zip("xfile.bin", b"hi");
    let (_d, path) = write_tmp(&bytes);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zip4n6"))
        .args(["list", &path])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("xfile.bin"));
}

#[test]
fn binary_bad_args_exits_2() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zip4n6"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage"));
}
