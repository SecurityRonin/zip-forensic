# Validation

Correctness is established against independent third-party oracles and real-tool
fixtures, not fixtures we both encoded and graded ourselves. The authoritative
format reference is the PKWARE APPNOTE.TXT ZIP specification
(<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>).

## The no-C-FFI guarantee (the project's reason for being)

`zip-core`'s runtime dependency tree contains only pure-Rust crates. The three
C-FFI libraries the `zip` crate pulls (`bzip2-sys`, `zstd-sys`, `lzma-sys`) are
absent:

```
cargo tree -p zip-core -e normal | grep -- -sys   # empty
```

`zip` (zip-rs) is retained ONLY as a `dev-dependency` differential oracle; it is
not in the normal tree and is never shipped to downstream consumers.

## Codec decode — tier 1

Each codec is validated byte-for-byte against a known plaintext payload carried in
a fixture produced by an **independent** encoder, decoded by zip-core's pure-Rust
path (`tests/data/README.md` records every generator command and hash):

| Method | Oracle / fixture source | Cross-check |
|--------|-------------------------|-------------|
| Stored (0), Deflate (8) | zip-rs writer (in-memory) | zip-rs reader + payload |
| Bzip2 (12) | zip-rs writer (C libbz2) | zip-rs reader + payload |
| Zstd (93) | zip-rs writer (C libzstd) | zip-rs reader + payload |
| Deflate64 (9) | 7-Zip `-mm=Deflate64` | payload (7z extraction = ground truth) |
| LZMA (14) | 7-Zip `-mm=LZMA` | payload (7z extraction = ground truth) |
| XZ (95) | Python `lzma` (FORMAT_XZ) in a hand-built method-95 container | payload (7z extraction = ground truth) |

For Bzip2/Zstd the encoder is a *different codebase* (the C library, via zip-rs)
from the decoder (pure-Rust `bzip2-rs`/`ruzstd`), so a match is genuine
cross-implementation agreement. zip-rs is deliberately NOT used to cross-check the
method-14 LZMA fixture — it fails to decode 7z's framing — so the third-party
fixture plus the known payload is the answer key there.

## Container structure — tier 1

- **Zip64**: hand-built fixtures where the central-directory base sizes are
  `0xFFFFFFFF` (resolved from the Zip64 extra field, id `0x0001`) and where the
  32-bit EOCD offset/count are sentinels (resolved via the Zip64 EOCD record +
  locator). Both are confirmed valid by `7z` extraction reproducing the payload.
- **Data descriptors** (GP flag bit 3): a Python `zipfile` stream-written archive.
- **Random access**: `read_at` is differentially compared, at a spread of
  offsets/lengths, to a full decompress-then-slice — on a synthetic stored-block
  fixture and (env-gated) on a real DFIR-Madness E01-in-zip.

## Robustness

Truncated/empty inputs error cleanly (never panic); the parser reads every field
through a bounds-checked reader; entry counts and buffered-decode output are
capped against allocation/decompression bombs; and three `cargo-fuzz` targets
(`archive`, `entry_decode`, `forensic`) assert "must not panic" over arbitrary
bytes.
