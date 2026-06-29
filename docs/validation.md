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

## Real-world artifacts (tier-1, env-gated)

A scan of ~2,400 real zip files across the local forensic corpora establishes the
**actual** method distribution and which methods can be validated on genuine
real-world data versus only on independent-tool fixtures:

| Method | Real-world zips found | Real-data validation |
|--------|-----------------------|----------------------|
| Stored / Deflate | thousands (every E01-in-zip, collection, memory dump) | **yes** — see below |
| Deflate64 (9) | a few real CTF artifacts | **yes** — see below |
| Bzip2 / LZMA / XZ | **none** (only our own fixtures) | not present in the wild; independent-tool fixtures + the zip-rs C-lib oracle are the appropriate tier-1 |
| AES / ZipCrypto | a real encrypted-malware sample | out of scope (zip-core does not decrypt) |

This matches the design premise: real forensic zips are overwhelmingly
Stored/Deflate, with Deflate64 appearing for very large (>4 GiB-window) files.

- **Deflate (real, multi-GB):** the DFIR-Madness "Stolen Szechuan Sauce"
  `DC01-E01.zip` holds a 2,524,848,357-byte Windows disk E01 as a normal-deflate
  entry (CRC `ff0ce1a7`). zip-core's native decode is compared **byte-for-byte to
  the separately-extracted E01** (an independent ground-truth answer key) in a
  single streaming pass, and its CRC-32 is verified at EOF.
  Test: `native_decode_matches_extracted_ground_truth`
  (env `ZIP_CORE_REAL_E01_ZIP` + `ZIP_CORE_REAL_E01_EXTRACTED`).
  Real-world note: this E01 uses *normal* deflate (Huffman), not level-0 stored
  blocks, so it exercises the full-decode path; the zero-copy stored-block
  `read_at` fast path is validated by the synthetic stored-block tests.
- **Deflate64 (real, 4 GiB):** the SecurityNik "TOTAL RECALL" memory-forensics CTF
  zip compresses a 4,293,816,320-byte Windows memory dump with Deflate64 (method 9,
  CRC `de173b7f`). zip-core decodes the entries and the recorded CRC-32 (the CTF
  author's tool is the independent oracle) is verified at EOF.
  Test: `deflate64_decodes_real_securitynik_ctf`
  (env `ZIP_CORE_REAL_DEFLATE64_ZIP`, `…_FULL=1` for the 4 GiB entry).

Per the fleet Test-Data standard these multi-GB artifacts are gitignored and
env-gated (the tests skip cleanly when the corpus is absent); they are catalogued
in `issen/docs/corpus-catalog.md`.

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
