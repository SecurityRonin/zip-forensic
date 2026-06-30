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

/// Single-entry zip whose EOCD declares the central directory lives on a later
/// disk (`cd_start_disk`/`this_disk` != 0) while the entry's own `disk_start` is
/// 0. This is what real Info-ZIP split archives look like on the last segment:
/// the data entries record disk 0, but the volume is multi-disk. Reading any
/// entry from this single segment cannot resolve the right bytes.
fn zip_multidisk_eocd(this_disk: u16, cd_start_disk: u16) -> Vec<u8> {
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
    o.extend_from_slice(&0u16.to_le_bytes()); // disk number start == 0 (on disk 0)
    o.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    o.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    o.extend_from_slice(&0u32.to_le_bytes()); // lfh offset
    o.extend_from_slice(name);
    let cd_size = o.len() - cd;
    o.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    o.extend_from_slice(&this_disk.to_le_bytes()); // number of this disk
    o.extend_from_slice(&cd_start_disk.to_le_bytes()); // disk with start of CD
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&(cd_size as u32).to_le_bytes());
    o.extend_from_slice(&(cd as u32).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o
}

#[test]
fn multidisk_eocd_fails_loud_even_with_disk0_entry() {
    // EOCD says CD is on disk 2 of a 2+-disk set; the entry records disk 0.
    // The single segment we hold cannot resolve the data, so reads must fail
    // loud — never silently return bytes from the wrong offset.
    let bytes = zip_multidisk_eocd(2, 2);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    // Enumeration still works: the central directory is wholly present.
    assert_eq!(ar.len(), 1);
    assert!(
        matches!(ar.by_index(0), Err(ZipCoreError::SpannedArchive { .. })),
        "a multi-disk EOCD must fail loud on read even when the entry's disk_start is 0"
    );
}

#[test]
fn nonzero_this_disk_alone_fails_loud() {
    // EOCD records this segment as disk 3 while cd_start_disk is 0 — still a
    // multi-volume set we can't resolve from one segment.
    let bytes = zip_multidisk_eocd(3, 0);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        ar.by_index(0),
        Err(ZipCoreError::SpannedArchive { disk: 3, .. })
    ));
}
