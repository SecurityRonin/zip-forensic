//! Secure-by-default tests: path-traversal names must be surfaced as a typed
//! refusal (`enclosed_name() == None`) so a caller extracting to disk cannot be
//! tricked into writing outside the destination. A forensic reader still EXPOSES
//! the raw `name()` (the malicious value is evidence); it just refuses to hand
//! back a path that escapes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::ZipArchive;

/// Minimal single-entry STORED zip with an arbitrary (possibly hostile) name.
fn stored_zip_named(name: &str) -> Vec<u8> {
    let payload = b"x";
    let nb = name.as_bytes();
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
    let mut out = Vec::new();
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
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
    out
}

fn enclosed(name: &str) -> Option<String> {
    let bytes = stored_zip_named(name);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let e = ar.by_index(0).unwrap();
    // The raw name is always preserved (evidence); enclosed_name is the safe view.
    assert_eq!(e.name(), name);
    e.enclosed_name()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
}

#[test]
fn rejects_parent_dir_traversal() {
    assert_eq!(enclosed("../../etc/passwd"), None);
    assert_eq!(enclosed("a/../../b"), None);
}

#[test]
fn rejects_absolute_and_drive_paths() {
    assert_eq!(enclosed("/etc/shadow"), None);
    assert_eq!(enclosed("C:\\Windows\\system32\\cmd.exe"), None);
}

#[test]
fn accepts_normal_relative_paths() {
    assert_eq!(
        enclosed("dir/sub/file.txt").as_deref(),
        Some("dir/sub/file.txt")
    );
    assert_eq!(enclosed("file.bin").as_deref(), Some("file.bin"));
}
