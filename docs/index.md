# zip-forensic

A pure-Rust, read-only ZIP toolkit for digital forensics: a container reader
(`zip-forensic-core`) that decodes every common entry codec with **no C-FFI dependencies**,
and an anomaly auditor (`zip-forensic`) that surfaces tamper signals a happy-path
reader would normalize away.

## Why it exists

The widely-used `zip` crate pulls three C libraries transitively to decompress
bzip2/zstd/lzma entries (`bzip2-sys`, `zstd-sys`, `lzma-sys`). A `forbid(unsafe)`,
pure-Rust forensic fleet cannot accept those, and Cargo feature unification makes
them un-droppable downstream. `zip-forensic-core` replaces the dependency with pure-Rust
decoders so the C libraries leave the build entirely.

## What you get

- **`zip-forensic-core`** — `ZipArchive` over any `Read + Seek`: EOCD + Zip64 + central
  directory + local headers, entry access by name/index, and decode for Stored,
  Deflate, Deflate64, Bzip2, Zstd, LZMA (method 14) and XZ — all pure Rust. CRC-32
  is verified on EOF; path-traversal names are refused by `enclosed_name()`;
  decompression output is capped against bombs.
- **Deflate-block-indexed random access** — an E01 stored in a ZIP at ~0%
  compression is a run of byte-aligned stored blocks, so `read_at(buf, offset)`
  seeks directly to any offset with no full inflation and no temp extraction.
- **`zip-forensic`** — `audit_path` / `audit_reader` emit graded
  `forensicnomicon` findings: central-directory vs local-header disagreements,
  `..`-traversal / absolute names, and data prepended before the first member.

See [Validation](validation.md) for how correctness is established.
