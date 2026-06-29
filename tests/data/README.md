# zip-forensic test data

Provenance for every committed test artifact (fleet Test-Data standard). Small,
synthetic-but-third-party-generated fixtures are committed; large real corpora
(E01-in-zip) are gitignored and env-gated (see `core/tests/differential.rs`).

## `codecs/` — per-codec decode fixtures (tier-1)

Each archive holds a single entry `file.bin` whose plaintext is the **same
deterministic payload**:

```
payload[i] = (i / 64) as u8,  for i in 0..20000
```

SHA-256 of the plaintext: `26560fa5bc1c428e425955954f88bfdd9e3766238a1d66c5586b34a3bc64574b`
(CRC-32 as listed by `unzip -v`: `ad430f3a`). This payload is the **answer key**;
`core/tests/codecs.rs` regenerates it and asserts byte-equality after decode.

| File | Method | Generator command | SHA-256 (archive) |
|------|--------|-------------------|-------------------|
| `deflate64.zip` | 9 (Deflate64) | `7z a -tzip -mm=Deflate64 -mx9 deflate64.zip file.bin` | `43d1f10a272525c8c5ef95828554a6082fe07f23727b12591c8d033cdd548c64` |
| `bzip2.zip`     | 12 (BZip2)    | `7z a -tzip -mm=BZip2 -mx9 bzip2.zip file.bin`         | `45d0dbe5c618d9b15a968789558399e9c32e2b27662be30b8b3f6ecb5076f569` |
| `lzma.zip`      | 14 (LZMA)     | `7z a -tzip -mm=LZMA -mx9 lzma.zip file.bin`           | `ab0fe9b27b4f58a1d1a86b2b267fc3fe98798ad3eaca1091ca12668632dd0d72` |
| `xz.zip`        | 95 (XZ)       | Python `lzma.compress(payload, format=FORMAT_XZ, preset=9)` wrapped in a hand-built method-95 container | `c1743ce93c1330322f8edb51eaa1aa73f321c0fd6d7d147a29ac6478757cf716` |

- **Generator:** 7-Zip (`7z` 24.x, Homebrew) — an independent third-party encoder;
  `xz.zip`'s stream is Python `lzma` (XZ), since no common tool writes method-95
  zips. Ground truth for all five is confirmed by `7z e` reproducing the payload.
- **Ground-truth check:** `7z e <archive>` reproduces the payload SHA above.
- **License/redistribution:** content is a trivially-regenerable numeric pattern
  with no third-party copyright; safe to commit.
- **Why 7z, not zip-rs, for these:** zip-rs cannot write Deflate64/LZMA, and it
  fails to *decode* 7z's method-14 LZMA framing. Bzip2 (12) and Zstd (93) are
  instead validated in-memory against the zip-rs writer/reader oracle (which uses
  the C libbz2/libzstd) — independent of zip-core's pure-Rust decoders.

## Large artifacts (gitignored)

`core/tests/differential.rs` reads a real DFIR-Madness E01-in-zip when
`ZIP_CORE_REAL_E01_ZIP` points at it. Not committed; document the corpus entry in
`issen/docs/corpus-catalog.md`.
