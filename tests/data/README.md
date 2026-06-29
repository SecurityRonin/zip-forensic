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
  the C libbz2/libzstd) — independent of zip-full-core's pure-Rust decoders.

## `structure/` — container-structure fixtures

Payload: `payload[i] = (i * 37) as u8, for i in 0..3000`. Consumed by
`core/tests/structure.rs`.

| File | What it exercises | Generator |
|------|-------------------|-----------|
| `zip64.zip` | `force_zip64` real-tool archive (zip64 extra in LFH, real CD sizes) | Python `zipfile`, `zf.open(force_zip64=True)` |
| `datadesc.zip` | data descriptor (GP flag bit 3) — written to an unseekable stream | Python `zipfile` to a non-seekable `RawIOBase` |
| `zip64_cd_extra.zip` | **CD** base sizes = 0xFFFFFFFF resolved from the Zip64 extra field (id 0x0001) | hand-built container (struct) |
| `zip64_eocd.zip` | **EOCD** sentinel offset/count resolved via the Zip64 EOCD record + locator | hand-built container (struct) |

The two hand-built zip64 fixtures are confirmed valid by an independent oracle:
`7z e` reproduces the payload byte-for-byte (SHA-256
`66539d934bf91e18d36aeda8c1de82da94c6a02d9b84a9c8e65e0d1a88072581`).

## `encrypted/` — decryption fixtures (tier-1)

Same 20 000-byte payload as `codecs/` (SHA-256
`26560fa5bc1c428e425955954f88bfdd9e3766238a1d66c5586b34a3bc64574b`), password
`Infected123`. Consumed by `core/tests/encryption.rs`.

| File | Encryption | Generator command |
|------|-----------|-------------------|
| `zipcrypto.zip` | traditional ZipCrypto | `7z a -tzip -pInfected123 -mem=ZipCrypto zipcrypto.zip file.bin` |
| `aes256.zip` | WinZip AES-256 (AE-2) | `7z a -tzip -pInfected123 -mem=AES256 aes256.zip file.bin` |

Ground truth confirmed by `7z e -pInfected123` reproducing the payload SHA above.
AES-128/192 and the fail-loud integrity paths (truncated/corrupted ciphertext,
wrong password) are covered by `crypto.rs` unit tests. A real-world ZipCrypto
sample (objective-see XLoader malware, password `infected`) is additionally
decrypted and cross-checked against the zip-rs oracle via
`ZIP_CORE_ZIPCRYPTO_ZIP` (bytes compared, never executed).

## Large real-world artifacts (gitignored, env-gated, tier-1)

These genuine third-party artifacts are NOT committed (multi-GB); they live in the
shared issen corpus and the tests read them in place when the env vars point at
them, skipping cleanly otherwise. Provenance is also in
`issen/docs/corpus-catalog.md`.

### Deflate — DFIR-Madness "Stolen Szechuan Sauce" `DC01-E01.zip`

- **Source:** James Smith / dfirmadness.com — case page
  <https://dfirmadness.com/the-stolen-szechuan-sauce/>, direct
  <https://dfirmadness.com/case001/DC01-E01.zip>.
- **Contents:** entry `E01-DC01/20200918_0347_CDrive.E01`, 2,524,848,357 bytes
  uncompressed, normal deflate, CRC-32 `ff0ce1a7`.
- **Ground truth:** the separately-extracted `.E01` file (byte-exact, same size).
- **Consumed by:** `core/tests/differential.rs::native_decode_matches_extracted_ground_truth`
  via `ZIP_CORE_REAL_E01_ZIP` + `ZIP_CORE_REAL_E01_EXTRACTED`
  (+ `ZIP_CORE_REAL_E01_ENTRY`, defaulted).
- **Redistribution:** dfirmadness.com terms; not redistributed here (gitignored).

### Deflate64 — SecurityNik "TOTAL RECALL" memory-forensics CTF zip

- **Source:** SecurityNik (Nik Alleyne) memory-forensics challenge.
- **Contents:** `SECURITYNIK-WIN-20231116-235706.dmp` — 4,293,816,320-byte Windows
  memory dump, Deflate64 (method 9), CRC-32 `de173b7f`; plus a small `.json`
  sidecar (Deflate64, CRC-32 `43437618`).
- **Ground truth:** the CRC-32 recorded by the author's archiver (verified at EOF).
- **Consumed by:** `core/tests/codecs.rs::deflate64_decodes_real_securitynik_ctf`
  via `ZIP_CORE_REAL_DEFLATE64_ZIP` (+ `…_FULL=1` for the 4 GiB entry).

### Method-distribution note (why bzip2/lzma/xz use synthetic fixtures)

A scan of ~2,400 real corpus zips found Stored/Deflate everywhere, Deflate64 in a
few large-file CTF artifacts, and **no** real-world zip using Bzip2/LZMA/XZ. Those
three methods are therefore validated against independent-tool fixtures (7z /
Python-lzma) plus the zip-rs C-lib oracle — the best available tier-1 absent any
real-world occurrence.
