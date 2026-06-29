//! Common ZIP extra fields are parsed and surfaced on the structural view:
//! NTFS timestamps (0x000a), Info-ZIP Unix extended timestamp (0x5455), and
//! Info-ZIP Unicode path/comment (0x7075 / 0x6375).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::ZipArchive;

/// Build a single-entry zip whose CD header carries `cd_extra`.
fn zip_with_cd_extra(name: &[u8], cd_extra: &[u8]) -> Vec<u8> {
    let data = b"x";
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
    o.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
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

fn extra_record(id: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&id.to_le_bytes());
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

#[test]
fn parses_ntfs_unix_and_unicode_extras() {
    // NTFS (0x000a): reserved(4) + tag 0x0001 size 0x18 + mtime/atime/ctime FILETIME
    let mut ntfs = Vec::new();
    ntfs.extend_from_slice(&0u32.to_le_bytes()); // reserved
    ntfs.extend_from_slice(&0x0001u16.to_le_bytes());
    ntfs.extend_from_slice(&0x0018u16.to_le_bytes());
    ntfs.extend_from_slice(&0x01D6_1234_5678_9ABCu64.to_le_bytes()); // mtime
    ntfs.extend_from_slice(&0x01D6_1111_2222_3333u64.to_le_bytes()); // atime
    ntfs.extend_from_slice(&0x01D6_4444_5555_6666u64.to_le_bytes()); // ctime

    // Unix extended timestamp (0x5455): flags=0x01 (mtime present) + i32 mtime
    let mut uxt = Vec::new();
    uxt.push(0x01);
    uxt.extend_from_slice(&1_600_000_000i32.to_le_bytes());

    // Unicode path (0x7075): version(1) + name-crc(4) + UTF-8 name
    let uname = "naïve/файл.txt";
    let mut up = Vec::new();
    up.push(1);
    up.extend_from_slice(&0u32.to_le_bytes());
    up.extend_from_slice(uname.as_bytes());

    let mut extra = Vec::new();
    extra.extend_from_slice(&extra_record(0x000a, &ntfs));
    extra.extend_from_slice(&extra_record(0x5455, &uxt));
    extra.extend_from_slice(&extra_record(0x7075, &up));

    let bytes = zip_with_cd_extra(b"plain.txt", &extra);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let e = &ar.structural_view().unwrap()[0].extra;

    assert_eq!(e.ntfs_mtime, Some(0x01D6_1234_5678_9ABC));
    assert_eq!(e.ntfs_atime, Some(0x01D6_1111_2222_3333));
    assert_eq!(e.ntfs_ctime, Some(0x01D6_4444_5555_6666));
    assert_eq!(e.unix_mtime, Some(1_600_000_000));
    assert_eq!(e.unicode_path.as_deref(), Some("naïve/файл.txt"));
}

#[test]
fn no_extras_is_all_none() {
    let mut ar = ZipArchive::new(Cursor::new(zip_with_cd_extra(b"f", &[]))).unwrap();
    let e = &ar.structural_view().unwrap()[0].extra;
    assert_eq!(e.ntfs_mtime, None);
    assert_eq!(e.unix_mtime, None);
    assert_eq!(e.unicode_path, None);
    assert_eq!(e.unicode_comment, None);
}
