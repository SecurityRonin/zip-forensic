#![no_main]
//! EOCD / Zip64 EOCD / central-directory / local-file-header parsing over
//! arbitrary bytes — parse + the structural view must never panic.
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut archive) = zip_core::ZipArchive::new(Cursor::new(data)) {
        let _ = archive.structural_view();
        let _ = archive.file_names().count();
    }
});
