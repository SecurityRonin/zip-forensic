//! Legacy/rare compression methods must be RECOGNIZED by name (so a forensic
//! report names them) and FAIL LOUD on decode — never silently mishandled.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use zip_core::{CompressionMethod, ZipArchive, ZipCoreError};

/// Minimal single-entry zip with an explicit compression method and a few bytes
/// of (meaningless) compressed data.
fn zip_with_method(method: u16) -> Vec<u8> {
    let name = b"f";
    let comp = b"xx";
    let mut o = Vec::new();
    o.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&4u32.to_le_bytes());
    o.extend_from_slice(&(name.len() as u16).to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(name);
    o.extend_from_slice(comp);
    let cd = o.len();
    o.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&20u16.to_le_bytes());
    o.extend_from_slice(&0u16.to_le_bytes());
    o.extend_from_slice(&method.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&0u32.to_le_bytes());
    o.extend_from_slice(&(comp.len() as u32).to_le_bytes());
    o.extend_from_slice(&4u32.to_le_bytes());
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
fn legacy_methods_recognized_and_fail_loud() {
    let cases = [
        (1u16, CompressionMethod::Shrunk),
        (2, CompressionMethod::Reduced),
        (5, CompressionMethod::Reduced),
        (6, CompressionMethod::Imploded),
        (10, CompressionMethod::DclImploded),
        (16, CompressionMethod::IbmCmpsc),
        (18, CompressionMethod::IbmTerse),
        (19, CompressionMethod::IbmLz77),
        (94, CompressionMethod::Mp3),
        (96, CompressionMethod::Jpeg),
        (97, CompressionMethod::WavPack),
        (98, CompressionMethod::Ppmd),
    ];
    for (raw, expected) in cases {
        let bytes = zip_with_method(raw);
        let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
        // Recognized by name in the structural view (no decode needed).
        let view = ar.structural_view().unwrap();
        assert_eq!(view[0].central.method, expected, "method {raw} naming");
        // Fails loud on decode — named, never silently mishandled.
        assert!(
            matches!(ar.by_index(0), Err(ZipCoreError::UnsupportedMethod(m)) if m == expected),
            "method {raw} must fail loud as {expected:?}"
        );
    }
}

#[test]
fn truly_unknown_method_preserves_raw_value() {
    let bytes = zip_with_method(1234);
    let mut ar = ZipArchive::new(Cursor::new(bytes)).unwrap();
    assert_eq!(
        ar.structural_view().unwrap()[0].central.method,
        CompressionMethod::Unknown(1234)
    );
}
