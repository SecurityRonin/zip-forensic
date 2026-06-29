#![no_main]
//! Entry decoding (every codec dispatch + CRC verify) over arbitrary bytes —
//! decoding any entry must never panic, regardless of malformed streams.
use std::io::{Cursor, Read};

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = zip_core::ZipArchive::new(Cursor::new(data)) else {
        return;
    };
    for i in 0..archive.len() {
        if let Ok(mut entry) = archive.by_index(i) {
            // Cap the drain so a (lying) huge size can't make the fuzzer OOM.
            let mut sink = std::io::sink();
            let _ = std::io::copy(&mut (&mut entry).take(1 << 20), &mut sink);
        }
    }
});
