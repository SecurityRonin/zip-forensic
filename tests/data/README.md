# Test data

## `oracle-infozip.zip`

| | |
|---|---|
| **Source** | Minted locally with Info-ZIP `Zip 3.0 (July 5th 2008)`, the macOS system `zip` |
| **Command** | `zip -r -q archive.zip hello.txt sub` |
| **SHA-256** | see `shasum -a 256 tests/data/oracle-infozip.zip` |
| **Contents** | `hello.txt` (10 B, `hello zip\n`) · `sub/nested.txt` (7 B, `nested\n`) · `sub/big.bin` (8192 B, byte *i* = `i % 251`) |
| **Licence** | Inputs authored here; container produced by Info-ZIP. No third-party content, freely redistributable. |
| **Used by** | `core/src/vfs.rs` tests via `mint_zip()` |

### Why it is committed rather than minted at test time

`mint_zip()` used to shell out to the system `zip` and return `None` when it was
absent, so nine tests carried an `eprintln!("skipping: …"); return;` arm. Those
arms were unreachable on any machine that HAS `zip` — every CI runner — so the
coverage gate could never satisfy them. They could not honestly be annotated
`// cov:unreachable` either, because they are genuinely reachable: on a machine
without `zip`, they run. A false invariant is worse than none.

Committing the bytes keeps the property that actually mattered — **the container
is authored by Info-ZIP, not by our own writer**, so a decode bug cannot pass by
agreeing with itself — while making the suite satisfiable from committed bytes
alone, with no installed tool.

Note the archive is minted WITHOUT `-X`. That flag excludes extra file
attributes, which strips the extended-timestamp (`UT`) field, and
`resolves_and_reads_hello` asserts `m.times.modified.is_some()`. Minting with
`-X` produces a 760-byte archive that fails that assertion; the committed one is
968 bytes and carries the timestamps.

A live-`zip` differential test belongs in a separate env-gated target, outside
the coverage gate, where skipping when the tool is absent is legitimate.
