# 0003 — Tiered validation against real third-party corpora

- Status: accepted
- Date: 2026-07-01

## Context

Tests you author yourself — both the fixture and the expected answer — inherit
your blind spots. A wrong decoder and a fixture encoded to the same wrong
assumption pass green together (the "LZNT1 trap"). For a forensic tool whose
output is evidence, that failure mode is unacceptable on any path that produces a
value an independent oracle could check.

## Decision

Label every empirical claim by **tier** (who confirms it) and require the tier to
match the risk:

- **Tier 1** — independent third party authored the artifact *and* the answer
  key, or real-world data checked by an independent oracle.
- **Tier 2** — real engine output confirmed by an independent oracle, but we
  chose the scenario.
- **Tier 3** — fixture and answer both authored here.

The gate: **a value-producing, oracle-feasible path (codec, decoder, crypto) may
never rest on tier-3 alone** — it must have a tier-1/tier-2 oracle. Tier-3 is
legitimate and kept for detection heuristics (correctness defined by rule + spec),
robustness/negative properties (backed by fuzz targets), and adversarial edge
cases real corpora lack. Real fixtures are sourced from public corpora (libzip,
Apache Commons Compress, Go `archive/zip`, zipdetails, python-libarchive-c) with
reference-CLI oracles (`zipdetails`, `bunzip2`, `zstd`, `7zz`, `unzip`).

## Consequences

- A committed corpus of real third-party fixtures backs codec decode, decryption,
  extra-field parsing, spanning, legacy-method refusal, and prepended/trailing
  detection at tier-1; SecureZIP strong-encryption/CD-signature at tier-2.
  Provenance, hashes and licenses live in `core/tests/data/README.md` and
  `tests/data/codecs/README.md`; the full map is in `../validation.md`.
- Moving off self-authored fixtures onto real artifacts surfaced and fixed four
  bugs invisible to synthetic tests: EOCD-level spanned detection, the
  CD-signature record embedded inside the EOCD `cd_size` span, NFD/mojibake
  filename byte handling, and parsing prepended-data (SFX/polyglot) archives.
- Tampering-signature rules (overlap, bidi, CD/LFH mismatch, CRC mismatch) remain
  tier-3 by nature — no benign real corpus contains them — with the fuzz suite as
  the runtime backstop.
