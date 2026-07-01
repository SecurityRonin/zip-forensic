# 0002 — Read/decrypt-only scope; recognize-and-refuse unsupported methods and encryption

- Status: accepted
- Date: 2026-07-01

## Context

The PKWARE APPNOTE.TXT ZIP format is large: dozens of compression methods
(including obsolete ones), several encryption schemes, writing, spanning, and
signing. Implementing all of it is a poor use of effort for a forensic reader,
and every extra codec/writer is attack surface. But a forensic tool must not go
silent on what it does not support — an "unknown" that hides the offending value
is a dead end for the investigator, and a decoder that emits plausible-but-wrong
bytes fabricates evidence.

## Decision

Scope `zip-forensic-core` to **read and decrypt only** — no writer. For anything
it cannot fully process, it **recognizes the feature by name and fails loud**
rather than guessing:

- Legacy/rare codecs (Shrink, Reduce, Implode, DCL-Implode, PPMd, MP3, JPEG,
  WavPack, IBM TERSE/LZ77/CMPSC) are mapped to named `CompressionMethod`
  variants; a decode attempt returns `UnsupportedMethod(method)`.
- PKWARE strong encryption (GP-flag bit 6 / extra `0x0017`) and masked central
  directories return `UnsupportedEncryption`, distinct from WinZip-AES `0x9901`
  and traditional ZipCrypto, which **are** decrypted.
- The central-directory digital-signature record (`0x05054b50`) is recognized and
  its length surfaced, but not cryptographically verified.
- Spanned/multi-disk archives fail loud (`SpannedArchive`) rather than reading
  bytes from the wrong segment.

## Consequences

- Correctness rests on fail-loud behavior: the reader never returns wrong bytes
  for an unsupported input.
- Decryption is validated to tier-1; the recognize/refuse-only paths (strong
  encryption, CD signature) have no public corpus and are validated to tier-2
  against a SecureZIP-produced sample — see
  [ADR 0003](0003-tiered-validation-real-corpora.md).
- The fleet writes zips in several crates, so replacing zip-rs is a **split
  migration**: read consumers move to `zip-forensic-core`; write consumers keep a
  feature-slimmed zip-rs (`default-features = false, features = ["deflate"]`).
  Tracked in `../migration.md`.
