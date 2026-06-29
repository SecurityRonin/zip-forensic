//! Spanned/split multi-disk archives: an entry whose data lives on another disk
//! (central-directory disk-start != 0) must fail loud — we don't reassemble split
//! volumes, and must never read bogus bytes from the wrong offset.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::{ZipArchive, ZipCoreError};

/// Single-entry zip whose CD header records `disk_start` (the disk holding the
/// entry's local header). 0 = this disk.
fn zip_with_disk_start(disk_start: u16) -> Vec<u8> {
    let name = b"f";
    let data = b"data";
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
    o.extend_from_slice(&0u16.to_le_bytes()); // extra len
    o.extend_from_slice(&0u16.to_le_bytes()); // comment len
    o.extend_from_slice(&disk_start.to_le_bytes()); // disk number start
    o.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    o.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    o.extend_from_slice(&0u32.to_le_bytes()); // lfh offset
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
fn entry_on_another_disk_fails_loud() {
    let bytes = zip_with_disk_start(1);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(
        matches!(ar.by_index(0), Err(ZipCoreError::SpannedArchive { .. })),
        "an entry on another disk must fail loud, not read the wrong offset"
    );
}

#[test]
fn single_disk_entry_still_reads() {
    // disk_start == 0 => normal single-file archive, must still work.
    let bytes = zip_with_disk_start(0);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(ar.by_index(0).is_ok());
}
