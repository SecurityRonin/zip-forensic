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

## Ground-truth values (from `zipdetails`, independent oracle)

| File | Entry | Field | Value |
|------|-------|-------|-------|
| `unicode.zip`  | `a/`         | UT mtime   | `1268678396` |
| `unicode.zip`  | `a/grün.png` | UT mtime   | `1268678259` |
| `unicode2.zip` | `a/`         | NTFS mtime | `130262190704904878` |
| `unicode2.zip` | `a/grün.png` | NTFS mtime | `129131482600000000` |
