# Validation

Correctness is established against independent third-party oracles and
real-world artifacts, not fixtures we both encoded and graded ourselves. Each
claim is labelled by **tier** — the trustworthiness of the check, not whether the
data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data validated by an independent oracle.
- **Tier 2** — real engine/tool output confirmed by an independent oracle, but we
  chose the scenario, so it can miss real-world quirks.
- **Tier 3** — fixture and expected answer both authored here; legitimate only
  where no external oracle exists (detection rules defined by spec, robustness
  properties, adversarial edge cases), never as the sole check of a
  value-producing path.

The authoritative format reference is the PKWARE APPNOTE.TXT ZIP specification
(<https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT>). Provenance,
hashes and licenses for every committed fixture are in
`core/tests/data/README.md` and `tests/data/codecs/README.md`.

## The no-C-FFI guarantee (the project's reason for being)

`zip-forensic-core`'s runtime dependency tree contains only pure-Rust crates. The
three C-FFI libraries the `zip` crate pulls (`bzip2-sys`, `zstd-sys`, `lzma-sys`)
are absent:

```
cargo tree -p zip-forensic-core -e normal | grep -- -sys   # empty
```

`zip` (zip-rs) is retained ONLY as a `dev-dependency` differential oracle; it is
not in the normal tree and is never shipped to downstream consumers.

## Codec decode — tier 1

Every codec is validated against a **real-world, third-party-authored** archive,
with ground truth supplied by an independent reference tool decoding the same
stream — never a payload we chose:

| Method | Real fixture (producer) | Independent oracle |
|--------|-------------------------|--------------------|
| Bzip2 (12) | libzip `regress/testbzip2.zip` (BSD-3) | `bunzip2 -c` |
| Zstd (93) | WinZip, zipdetails corpus (Artistic-1.0) | `zstd -d` |
| Deflate64 (9) | WinZip, zipdetails corpus | `7zz x` |
| LZMA (14) | WinZip, zipdetails corpus | `7zz x` |
| XZ (95) | WinZip, zipdetails corpus | `7zz x` |
| Stored (0), Deflate (8) | exercised by the real-world fixtures above and the env-gated real artifacts below | — |

The decoder (pure-Rust `bzip2-rs`/`ruzstd`/`lzma-rs`/`flate2`/`deflate64`) is a
different codebase from each oracle, so a byte-match is genuine cross-tool
agreement. zip-rs is deliberately NOT used to cross-check the WinZip method-14
LZMA framing — it rejects that framing — so the `7zz` reference decode is the
answer key there. Tests: `core/tests/codecs.rs`.

## Decryption — tier 1

`zip-forensic-core` decrypts encrypted entries via
`by_index_decrypt`/`by_name_decrypt` (plain `by_*` refuses an encrypted entry —
secure by default). Validation uses libzip's regress encrypted archives, which
ship with **documented passwords and plaintext** (an independent answer key):

| Scheme | Implementation | Tier-1 fixture (password → plaintext) |
|--------|----------------|----------------------------------------|
| WinZip AES 128/192/256 | audited RustCrypto (`aes`/`ctr`/`hmac`/`sha1`/`pbkdf2`) — no primitive hand-rolled | libzip `encrypt-aes{128,192,256}.zip`, `foofoofoo` → `encrypted\n` |
| Traditional ZipCrypto | the ZIP format's own legacy cipher, implemented per APPNOTE (decrypt-only) | libzip `encrypt.zip`, `foo` → `foo\n` |

A wrong password is rejected (`WrongPassword`), never returned as garbage
plaintext. For AES the PBKDF2 verifier is checked up front and the HMAC-SHA1
authentication code is verified at EOF; AE-2 omits the CRC, so its integrity
rests on the HMAC. Writing/encryption is out of scope: this is a read/decrypt-only
forensic reader. Tests: `core/tests/realworld_corpus.rs`.

## PKWARE strong encryption & central-directory signature — tier 2

Two SecureZIP-only features appear in no public corpus; both are recognize/refuse
paths (no decode step). They are validated against a real archive produced by
**SecureZIP for Mac v14.50.32** (a throwaway `lorem.txt`, strong-encrypted and
central-directory-signed with a no-identity self-signed cert), cross-checked with
`zipdetails`:

| Feature | Markers | Behavior |
|---------|---------|----------|
| PKWARE strong encryption | GP-flag bit 6 + extra `0x0017`, AES-256, certificate-based | refused with `UnsupportedEncryption` (distinct from WinZip-AES `0x9901`, which is decrypted) |
| Central-directory digital signature | `0x05054b50` record | recognized; length surfaced on the summary (not verified) |

Tier-2 because we chose the scenario; it is the strongest tier obtainable without
an in-the-wild SecureZIP sample. Tests: `core/tests/realworld_corpus.rs`.

## Container structure & anomalies — tier 1 on real artifacts

| Capability | Tier-1 real artifact | Check |
|------------|----------------------|-------|
| Spanned / multi-disk | Apache Commons Compress split archives (WinRAR, Info-ZIP, Info-ZIP zip64) | every entry fails loud `SpannedArchive`; enumeration still works |
| Unix timestamp `0x5455` | libarchive (CC0) + Info-ZIP (Go testdata, BSD) | parsed value matches `zipdetails` |
| NTFS time `0x000a` | libarchive + 7-Zip + WinRAR | parsed value matches `zipdetails` |
| Unicode path `0x7075` | WinZip (Apache), libzip (BSD), WinZip (Artistic) | matches `zipdetails` UnicodeName |
| Unicode comment `0x6375` | libzip (BSD), WinZip (Artistic) | matches `zipdetails` UnicodeCom |
| Legacy codecs (Shrink, Implode, PPMd) | Apache Commons Compress / zipdetails | `unzip` proves genuine stream; decoder names the method and refuses |
| Prepended data (SFX/polyglot) | Go testdata `test-prefix.zip` (BSD) | parsed, read and CRC-verified through a 43-byte stub; `PrependedData{43}` reported |
| Trailing data | Go testdata `test-trailing-junk.zip` (BSD) | `TrailingData{14}` reported |

The real fixtures surfaced — and we fixed — bugs a self-authored fixture could
not: EOCD-level spanning detection, the CD-signature record embedded inside the
EOCD `cd_size` span, NFD/mojibake filename handling, and parsing prepended-data
(SFX/polyglot) archives.

### Analyzer false-positive / sensitivity checks — tier 1

`forensic/tests/realworld_audit.rs` runs the anomaly analyzer over the real
corpus: **specificity** — every well-formed benign archive produces zero
anomalies (no false positives); **sensitivity** — libzip's
`test-cp437-comment` file, which genuinely carries control-character entry names,
is flagged `NAME-CONTROL`.

## Tampering signatures — tier 3 (by nature)

The remaining anomaly rules — overlapping member data, RTL/bidi override names,
central-directory vs local-file-header field mismatch, CRC-32 mismatch — detect
deliberate tampering/attack signatures that do not occur in benign real corpora,
so there is no third-party known-answer artifact to validate against. Correctness
is defined by the rule plus the spec; the synthetic fixtures in
`forensic/tests/audit.rs` specify behavior. The runtime backstop is the fuzz
suite (must-not-panic), not an oracle.

## Real-world artifacts — tier 1, env-gated

The multi-GB real artifacts are gitignored and env-gated (tests skip cleanly when
absent; catalogued in `issen/docs/corpus-catalog.md`):

- **Deflate (real, multi-GB):** the DFIR-Madness "Stolen Szechuan Sauce"
  `DC01-E01.zip` holds a 2,524,848,357-byte Windows disk E01 as a normal-deflate
  entry (CRC `ff0ce1a7`). zip-forensic-core's native decode is compared
  byte-for-byte to the separately-extracted E01 (independent ground truth) in a
  single streaming pass; CRC-32 verified at EOF. Tests:
  `native_decode_matches_extracted_ground_truth` (env `ZIP_CORE_REAL_E01_ZIP` +
  `ZIP_CORE_REAL_E01_EXTRACTED`) and the random-access `read_at_matches_real_e01_zip`.
- **Deflate64 (real, 4 GiB):** the SecurityNik "TOTAL RECALL" memory-forensics CTF
  zip compresses a 4,293,816,320-byte Windows memory dump with Deflate64 (method
  9). zip-forensic-core decodes the entries and the recorded CRC-32 (the CTF
  author's tool is the independent oracle) is verified at EOF. Test:
  `deflate64_decodes_real_securitynik_ctf` (env `ZIP_CORE_REAL_DEFLATE64_ZIP`,
  `…_FULL=1` for the 4 GiB entry).

This matches the design premise: real forensic zips are overwhelmingly
Stored/Deflate, with Deflate64 appearing for very large (>4 GiB-window) files.

## Robustness

Truncated/empty inputs error cleanly (never panic); the parser reads every field
through a bounds-checked reader; entry counts and buffered-decode output are
capped against allocation/decompression bombs; and three `cargo-fuzz` targets
(`archive`, `entry_decode`, `forensic`) assert "must not panic" over arbitrary
bytes.
