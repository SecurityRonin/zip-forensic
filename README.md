# zip-forensic

[![Crates.io: zip-core](https://img.shields.io/crates/v/zip-core?label=zip-core)](https://crates.io/crates/zip-core)
[![Crates.io: zip-forensic](https://img.shields.io/crates/v/zip-forensic?label=zip-forensic)](https://crates.io/crates/zip-forensic)
[![Docs.rs](https://img.shields.io/docsrs/zip-core?label=docs.rs)](https://docs.rs/zip-core)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/zip-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/zip-forensic/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://securityronin.github.io/zip-forensic/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Fuzzed](https://img.shields.io/badge/fuzzed-cargo--fuzz-success.svg)](fuzz/)

**Audit a ZIP for tampering, and read every common codec — in pure Rust, with zero C-FFI dependencies.**

```rust
// Surface where an archive's central directory disagrees with its local headers —
// the classic post-hoc-edit signal a happy-path reader silently trusts.
for anomaly in zip_forensic::audit_path("evidence.zip".as_ref())? {
    println!("[{:?}] {}: {}", anomaly.severity, anomaly.code, anomaly.note);
}
// [High] ZIP-CD-LFH-MISMATCH: entry 3 (report.docx): central-directory crc32
//   (0x1a2b3c4d) disagrees with the local file header (0x00000000) — consistent
//   with a post-hoc edit of one copy
```

That's it — point it at a zip and read graded findings. Each is an observation
("consistent with"), never a verdict, and converts to a
[`forensicnomicon`](https://crates.io/crates/forensicnomicon) `Finding`.

## Read entries without the C libraries

`zip-core` parses the container and decodes every common method with **only
pure-Rust crates** — the three C libraries the popular `zip` crate pulls
(`bzip2-sys`, `zstd-sys`, `lzma-sys`) are gone:

```rust
use std::io::Read;
let mut archive = zip_core::ZipArchive::new(std::fs::File::open("eg.zip")?)?;
let mut entry = archive.by_name("data.bin")?;   // Stored/Deflate/Deflate64/Bzip2/Zstd/LZMA/XZ
let mut bytes = Vec::new();
entry.read_to_end(&mut bytes)?;                 // CRC-32 verified on EOF; fails loud on mismatch
```

```console
$ cargo tree -p zip-core -e normal | grep -- -sys
$            # empty — no C-FFI in the runtime tree
```

Encrypted entries decrypt with a password — traditional ZipCrypto and WinZip AES
(128/192/256), the latter on audited RustCrypto with HMAC verification:

```rust
let mut entry = archive.by_name_decrypt("secret.bin", b"password")?;
// plain by_name() refuses an encrypted entry — secure by default
```

## Random-access a disk image inside a zip — no extraction

A forensic image stored in a ZIP at ~0% compression is, at the deflate level, a
run of byte-aligned *stored* blocks. `zip-core` indexes them so any offset is
addressable directly, with no full inflation and no temp spill:

```rust
let entry = zip_core::open_entry("case.zip".as_ref(), "image.E01")?;
let mut buf = vec![0u8; 4096];
entry.read_at(&mut buf, 1_000_000_003)?;        // positioned read, lock-free, no decompression from start
```

## Install

```toml
[dependencies]
zip-core = "0.1"        # the reader
zip-forensic = "0.1"    # the auditor
```

## Safety

`#![forbid(unsafe_code)]`, panic-free on untrusted input (bounds-checked reads,
entry-count and decompression-bomb caps), `enclosed_name()` refuses
path-traversal names, and three `cargo-fuzz` targets assert the parser, decoder,
and audit pipeline never panic. Correctness is established against independent
oracles — see the [validation notes](https://securityronin.github.io/zip-forensic/validation/).

---

[Privacy Policy](https://securityronin.github.io/zip-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/zip-forensic/terms/) · © 2026 Security Ronin Ltd
