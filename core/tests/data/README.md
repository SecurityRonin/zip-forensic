# Test data provenance

Real-world, third-party-authored ZIP archives used for **tier-1** validation
(an independent third party authored the artifact; ground truth is derived from
an independent oracle — `zipdetails`, the Perl byte-level parser — not from this
crate). See `core/tests/realworld_corpus.rs`.

## `unicode.zip`

- **Source**: [python-libarchive-c](https://github.com/Changaco/python-libarchive-c)
  test suite, `tests/data/unicode.zip` (authored by the project maintainers).
- **Obtained from**: the `python-libarchive-c-5.1` conda package
  (`info/test/tests/data/unicode.zip`); identical to the upstream repo file.
- **md5**: `7a3067c10240c60609697c937afb3280`
- **sha256**: `02472561b6c03a80652ba84350a14a6e2088d6b31832f9a25ac66b1956f080d9`
- **size**: 668 bytes
- **License / redistribution**: CC0 1.0 Universal (public domain dedication) —
  the project's `LICENSE.md`. Freely redistributable.
- **Contents**: two entries (`a/`, `a/grün.png`) carrying Info-ZIP Unix extended
  timestamps (extra id `0x5455`) plus the Unix uid/gid extra (`0x7875`, which our
  parser does not consume — exercises the skip-unknown path on real data) and a
  non-ASCII filename.
- **Use case**: `realworld_corpus.rs` cross-checks the parsed `unix_mtime` for
  each entry against the `zipdetails` central-directory ground truth.

## `unicode2.zip`

- **Source**: same project/file (`tests/data/unicode2.zip`).
- **Obtained from**: `info/test/tests/data/unicode2.zip`.
- **md5**: `486494d16d82add45fd00b8f0838237b`
- **sha256**: `6380e032416b906b7152538be2962a757f115a8b39c448181c43a3e149cd8d66`
- **size**: 636 bytes
- **License / redistribution**: CC0 1.0 Universal. Freely redistributable.
- **Contents**: two entries (`a/`, `a/grün.png`) carrying NTFS FileTimes (extra
  id `0x000a`) as Windows FILETIME ticks, including sub-second precision
  (`490487800 ns` on `a/`). The second filename is genuine real-world mojibake:
  the NFD bytes `cc 88` (U+0308) were misdecoded as CP437 (`╠`, `ê`) and
  re-encoded to UTF-8 (`e2 95 a0 c3 aa`). The parser surfaces the exact stored
  bytes rather than normalizing or repairing them.
- **Use case**: `realworld_corpus.rs` cross-checks the parsed `ntfs_mtime` for
  each entry against the `zipdetails` central-directory ground truth.

## `utf8-winzip-test.zip`

- **Source**: [Apache Commons Compress](https://github.com/apache/commons-compress)
  test suite, `src/test/resources/utf8-winzip-test.zip` (created with WinZip).
- **md5**: `f19a5a9e4ea9db862c0b092062dc5bb1`
- **sha256**: `fd5aeb74f430739a93b21f107237f74f31de5a59c66729dab68281f47ed1ec61`
- **size**: 569 bytes
- **License / redistribution**: Apache License 2.0 (the project's `LICENSE.txt`).
- **Contents**: three entries. Two store a non-ASCII name in CP437 in the main
  filename field (`€`→`0x80`, `Ö`→`0x99`) plus an Info-ZIP Unicode Path extra
  (`0x7075`, version + name-CRC + UTF-8) carrying the true name; one is ASCII.
- **Use case**: `realworld_corpus.rs` cross-checks the parsed `unicode_path`
  against the `zipdetails` "UnicodeName" for each entry.

## `split_zip_created_by_winrar.zip` / `split_zip_created_by_zip.zip`

- **Source**: Apache Commons Compress,
  `src/test/resources/COMPRESS-477/split_zip_created_by_{winrar,zip}/…` — the
  **final segment** of a multi-volume archive created by WinRAR and Info-ZIP
  respectively (the `.z01`/`.z02` data segments are not needed: the test proves
  we refuse without them).
- **md5**: `04e122a559eebcc17d0a45fa0c58c61b` / `0230669293d8d6083e488250febe84d7`
- **sha256**: `ea2d067a99a38f10288b2eed4543337719a41b0e6b8585a87f8728e5e317410a` /
  `fb86d35f40656889434d6e69b1055d11dfb44d3d68555a74891f187e6dc3333c`
- **size**: 50536 / 57763 bytes
- **License / redistribution**: Apache License 2.0.
- **Contents**: central directory + EOCD marking the CD on disk 2
  (`disk_number` / `cd_start_disk` == 2); 279 and 272 entries respectively.
- **Use case**: `realworld_corpus.rs` confirms enumeration works but every entry
  fails loud (`SpannedArchive`) — we hold only the last segment.

## Go `archive/zip` testdata (BSD-3-Clause)

From the Go standard library test suite
([golang/go](https://github.com/golang/go/tree/master/src/archive/zip/testdata)),
the `time-*`/`unix` corpus zips the same content with different engines —
purpose-built for multi-producer coverage. License: BSD-3-Clause (Go `LICENSE`).

| Committed name | Upstream | Producer | Extra | size | sha256 (short) |
|---|---|---|---|---|---|
| `ntfs-7zip.zip`   | `time-7zip.zip`   | 7-Zip   | NTFS 0x000a | 150 | `12e1b7b7…` |
| `ntfs-winrar.zip` | `time-winrar.zip` | WinRAR  | NTFS 0x000a | 150 | `058b9c05…` |
| `unixtime-infozip.zip` | `time-infozip.zip` | Info-ZIP | UT 0x5455 | 166 | `0e129eb3…` |
| `unixtime-infozip-multi.zip` | `unix.zip` | Info-ZIP | UT 0x5455 (4 entries) | 620 | `ae84fe91…` |

## Legacy compression codecs (Apache-2.0)

From Apache Commons Compress; `unzip` extracts both (oracle confirming they are
genuine streams). Our decoder recognizes the method and refuses to decode.

| Committed name | Upstream | Method | size | sha256 (short) |
|---|---|---|---|---|
| `shrunk.zip`   | `SHRUNK.ZIP` | Shrink (1) | 352 | `7403088a…` |
| `imploded.zip` | `imploding-8Kdict-3trees.zip` | Implode (6) | 4251 | `88d2bf6c…` |

## Third spanned producer (Apache-2.0)

| Committed name | Upstream | Producer | size | sha256 (short) |
|---|---|---|---|---|
| `split_zip64.zip` | `COMPRESS-477/.../split_zip_created_by_zip_zip64.zip` | Info-ZIP (zip64) | 69177 | `b647a24b…` |

## Ground-truth values (from `zipdetails`, independent oracle)

| File | Entry | Field | Value |
|------|-------|-------|-------|
| `unicode.zip`  | `a/`         | UT mtime   | `1268678396` |
| `unicode.zip`  | `a/grün.png` | UT mtime   | `1268678259` |
| `unicode2.zip` | `a/`         | NTFS mtime | `130262190704904878` |
| `unicode2.zip` | `a/grün.png` | NTFS mtime | `129131482600000000` |
| `utf8-winzip-test.zip` | #1 | Unicode Path (0x7075) | `€_for_Dollar.txt` |
| `utf8-winzip-test.zip` | #2 | Unicode Path (0x7075) | `Ölfässer.txt` |
| `split_zip_created_by_winrar.zip` | (all 279) | read | `SpannedArchive` |
| `split_zip_created_by_zip.zip`    | (all 272) | read | `SpannedArchive` |
