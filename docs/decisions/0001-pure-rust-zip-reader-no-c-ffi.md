# 0001 — Pure-Rust ZIP reader with no C-FFI dependencies

- Status: accepted
- Date: 2026-07-01

## Context

The SecurityRonin forensic fleet is `#![forbid(unsafe_code)]`. The widely-used
`zip` crate (zip-rs) decompresses bzip2/zstd/lzma entries by pulling three C
libraries transitively — `bzip2-sys`, `zstd-sys`, `lzma-sys`. Cargo unifies
features across the whole build, so a single full-featured `zip` dependency
*anywhere* in the graph re-enables those C libraries for every crate — they
cannot be dropped downstream by a consumer that only reads Stored/Deflate.

A forensic reader also has stricter needs than a general archiver: it must fail
loud on malformed input, never silently produce wrong bytes, and remain
auditable end-to-end.

## Decision

Build `zip-forensic-core`: a pure-Rust ZIP container reader that decodes every
common method with only pure-Rust crates
(`flate2`/`deflate64`/`bzip2-rs`/`ruzstd`/`lzma-rs`/`crc32fast`). The runtime
dependency tree contains no `*-sys` crate. `zip` (zip-rs) is retained **only** as
a `dev-dependency` differential oracle; it never ships to consumers. The library
name is decoupled from the package: `[lib] name = "zip_core"`, so imports stay
`use zip_core::…` regardless of the published crate name.

## Consequences

- The no-C-FFI guarantee is verifiable:
  `cargo tree -p zip-forensic-core -e normal | grep -- -sys` is empty.
- The MSRV floor is set by the pure-Rust decoders (`ruzstd` 0.8.3 → 1.87), not by
  a policy choice.
- The published package name is `zip-forensic-core` (the ideal `zip-core` was
  taken on crates.io; an interim `zip-full-core` was rejected as overstating
  coverage). The `zip_core` lib name keeps all call sites stable.
- Consumers that *write* zips are not served by a read-only reader, which forces
  a split fleet migration — see [ADR 0002](0002-read-decrypt-only-recognize-and-refuse.md).
  The fleet execution plan lives in the issen workspace
  (`docs/plans/2026-07-01-drop-cffi-zip-fleet-migration.md`).
