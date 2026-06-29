# Fleet migration: dropping the C-FFI `zip` crate

This page records the verified plan to move the SecurityRonin fleet off the
third-party `zip` crate (zip-rs) and its three C-FFI libraries (`bzip2-sys`,
`zstd-sys`, `lzma-sys`). The migration runs **after** `zip-forensic-core` / `zip-forensic`
are published to crates.io, and it touches several repositories — it is executed
as one wave, not from this repo.

## Key correction to the original plan

The original scoping assumed the fleet is **read-only** ("we never need to write
zips"). A direct audit shows that is **not** the case: zip-rs's `ZipWriter` is used
to *create* zips in many crates — verified usages include:

- `issen-archive/src/extract.rs` (re-packaging)
- `issen-parser-velociraptor/src/{lib,extract,probe}.rs`
- `issen-qcow2/src/lib.rs`, `issen-aff4/src/lib.rs`
- `aff4/aff4/src/{lib,testutil}.rs`
- and write/round-trip paths in several other `issen-*` crates.

`zip-forensic-core` is **read/decompress-only by design** and will not gain a writer.
Therefore the wave is a **split migration**, not a wholesale replacement.

## Compatibility audit (read surface)

Every read-side zip-rs API the fleet uses is covered by `zip-forensic-core`:

| zip-rs API | zip-forensic-core equivalent | Status |
|------------|---------------------|--------|
| `ZipArchive::new(reader)` | `ZipArchive::new` | covered |
| `.len()` / `.by_index(i)` / `.by_name(s)` | same | covered |
| `ZipFile::name/size/compressed_size/crc32/compression/is_dir` | same | covered |
| `ZipFile::data_start()` (in-place Stored window — `issen-unpack/backing.rs`) | `data_start()` | covered |
| `impl Read for ZipFile` (+ `take().read_to_end()` bomb guard) | `impl Read` | covered |
| `CompressionMethod::{Stored,Deflated,...}` | same enum | covered |
| `ZipArchive::by_index_raw(i)` (`velociraptor/probe.rs:31`) | — | **GAP** |

`backing.rs` — the fleet's core reader and the most demanding consumer (in-place
Stored window via `data_start()` + `compressed_size()`) — migrates with no logic
change.

### The one read gap: `by_index_raw`

`issen-parser-velociraptor/src/probe.rs` uses `by_index_raw` to inspect entry
headers without setting up decryption/decompression. `zip-forensic-core` covers this need
two ways: `structural_view()` already exposes per-entry header fields without
decoding, and a thin `by_index_raw`-style accessor can be added to `zip-forensic-core` when
velociraptor is migrated (mirror the zip-rs name for a mechanical port).

## The write paths keep a *slimmed* zip-rs

Write code stays on zip-rs, but the dependency is declared
`default-features = false` with only the pure-Rust write features it needs
(`deflate` → miniz_oxide; never `bzip2`/`zstd`/`lzma`). Because Cargo unifies
features across the whole build, **every** zip-rs dependency in the unified graph
must be slim — a single full-featured `zip = "2"` anywhere re-enables the C libs
for everyone. So the wave must, in one pass:

1. Repoint all **read** consumers from `zip` to `zip-forensic-core`.
2. Change every remaining (write) `zip` dependency to
   `zip = { version = "2", default-features = false, features = ["deflate"] }`.
3. Confirm no crate in the graph still pulls full-featured `zip`.

## Acceptance test

From the issen workspace root, after the wave:

```
cargo tree -e features --workspace | grep -E 'bzip2-sys|zstd-sys|lzma-sys'   # must be EMPTY
```

This is the single success criterion for the C-FFI removal across the fleet.

## Repos in scope

`issen` workspace (read consumers → `zip-forensic-core`; write consumers → slim zip-rs) and
`aff4` (same split). The container crates `qcow2-forensic` / `vhd` /
`vmdk-forensic` / `vhdx-forensic` were checked and pull **no** `zip` dependency, so
they need no change.
