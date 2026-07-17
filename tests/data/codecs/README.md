# Codec decode fixtures — provenance & tiers

Consumed by `core/tests/codecs.rs`. Tier = who chose the scenario.

## Tier-1 (real-world third-party artifact + independent reference oracle)

| File | Source / producer | Method | Oracle | Decodes to |
|---|---|---|---|---|
| `realworld-bzip2-libzip.zip` | [nih-at/libzip](https://github.com/nih-at/libzip) `regress/data/testbzip2.zip` (BSD-3) | BZIP2 (12) | `bunzip2 -c` on the raw entry | `abac-repeat.txt` → 60 bytes (`aaaa…/bbbb…/aaaa…/cccc…`) |
| `realworld-zstd-winzip.zip` | WinZip, via [pmqs/zipdetails](https://github.com/pmqs/zipdetails) `0003-winzip/et-zstd` (Artistic-1.0) | Zstandard (93) | `zstd -d` on the raw frame | `lorem.txt` → 446 bytes (see `realworld-zstd-winzip.expected`) |

`realworld-zstd-winzip.expected` is the committed `zstd -d` decode of the frame
(the oracle's answer key). The bzip2 expected is embedded in the test.

## Tier-2 (real encoder, but the payload is ours)

`deflate64.zip` (9), `lzma.zip` (14), `xz.zip` (95): produced by `7z` / Python
`lzma` from the deterministic payload `(0..20_000).map( |i| (i/64) as u8)` — see
`codecs::payload()`. Real encoder bitstream, our chosen scenario.

`bzip2.zip` (12): same synthetic payload, used by `coverage.rs` to exercise the
`read_at`-at-offset bzip2 fallback path (needs the 20 KB payload the 60-byte
real-world bzip2 fixture can't provide). Coverage fixture, not a correctness oracle.

`seek-deflate64.zip` (9): a genuinely-compressed Deflate64 member exercising the
checkpoint-indexed **seek** path (`core/src/deflate64_seek.rs`). Deterministic,
independently-reconstructed content (the test rebuilds the exact bytes), so the
seek oracle is ground truth, not self-consistency. Generated on the host with:

```sh
python3 -c "
with open('bigfile.txt','wb') as f:
    for i in range(4096):
        f.write(('%08d the quick brown fox jumps over the lazy dog - lorem ipsum dolor sit amet consectetur\n' % i).encode('ascii'))
"
7zz a -tzip -mm=Deflate64 -mx=9 seek-deflate64.zip bigfile.txt
```

- `bigfile.txt`: 385024 bytes, sha256
  `718d8d970d7e01420f932e53161e25d8c59ef056f73a9014b70d57f52a19ddef`
- entry `bigfile.txt`: method 9 (Deflate64), 385024 → 8605 compressed
- 7zz version: p7zip/7-Zip (Homebrew `7zz`), `-mm=Deflate64 -mx=9`

## Real-world, env-gated (tier-1 when run)

The SecurityNik Deflate64 CTF zip (`ZIP_CORE_REAL_DEFLATE64_ZIP`) and the
DFIR-Madness E01-in-zip (`ZIP_CORE_REAL_E01_ZIP`, in `differential.rs`).
