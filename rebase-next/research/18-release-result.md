# ReBase Next 0.2 release result

**D1–D6 accepted, 2026-10-22.** The bounded backend and developer-tool release
is usable as a real HTTP service and repeatable harness. Work remains isolated
inside `rebase-next/`. [Deployment](../docs/deployment.md),
[developer tools](../docs/developer-tools.md), [identity](../docs/server.md) and
[storage lifecycle](../docs/storage.md) supply runnable instructions.

## Shipped scope

One Rust binary hosts the compiled ten-public-contract calculation model with
protected private output roles. It exposes authenticated structured operations,
fresh transaction-scoped DAG authority, separate owners/readers, exact integer
bindings, bounded indexed reads, causal settlement, historical invariants and
durable receipt/replay behavior. Operator commands validate and explain the
model, plan fixtures, inspect state, back up, restore, reset and archive receipts.

The small Python client composes ordinary calls with explicit inputs. It writes
private, durable mutation plans before submission, checks target identity and
retains the original context through uncertain outcomes. It does not hide schema
rules, refresh old contexts or install a second calculation implementation.
Standard UUIDv5 namespaces allow independent instances of the authored fixture.

The data contract remains `rebase-store-2` / `rebase-calculation-contract-1`, with
model `dc1f590815e66b699e3b2ae62556c03c65088fdcf5b7fb30c97f5f75d129bc39`.
Version 0.2 changes the tooling/release envelope without reinterpreting D4 stores.

## Executed acceptance

- All **39 Rust tests** pass in optimized release mode, including exact algebra,
  structural corruption, authority, revocation, receipt atomicity, bounded reads,
  deadlines with retained admission and verified lifecycle behavior.
- **Six Python controls** exercise lost/truncated/misidentified/ambiguous/
  duplicate-key responses, rejected redirects, private no-clobber plan files,
  expiry and real TLS trust/hostname verification.
- The public developer workflow creates two independent fixture instances,
  changes the first report from **150 to 100**, preserves the second, rejects
  stale and misdirected work, replays after restart and rejects archived contexts.
- At **64 public sources plus ten private outputs**, eight concurrent copies of
  one request produce one commit; eight independently identified competing edits
  produce one winner and seven stale-version rejections. An extra source rejects
  without changing the public inventory or creating a receipt.
- **128 atomic date moves and 1024 concurrent root reads** preserve settled
  arithmetic. Complete pages match authored UUID inventory; bounded existence
  remains unknown until exhaustion, and a cursor becomes stale after a write.
- After acknowledged writes, forced process termination/reopen preserves values
  and the last receipt. Replay does not advance state. Complete integrity passes
  at revision **133**, with **74 records, 14 nodes and 130 active receipts**.
  Verified backup/restore also passes through the restored HTTP service.
- Cargo formatting/Clippy pass. Cargo-audit 0.22.2 finds **zero vulnerabilities
  and warnings among 152 dependencies**, using 1348 advisories at database commit
  `59ef7abf8ce56ea80fe7eba97ba3835449009fa4`.
- The systemd template passes `systemd-analyze verify` with the built executable
  substituted for its installation path. No system service was installed.
- An isolated 108-file Git source snapshot builds through its explicit manifest
  using the shared dependency cache and produces the **identical release binary**.
  Its copied client passes all six controls; its copied harness passes the full
  workflow plus eight additional atomic moves and 32 concurrent reads. All
  executable/model/tool fingerprints match the accepted source tree.

The existing independent native/local source-oracle evidence remains at D4.
Source fingerprints confirm unchanged calculation, binding, storage and authority
semantics; those corpora were not rerun for client/deployment changes.

## Measurements and what they establish

The corrected client run on Linux x86_64, 12 logical CPUs and Python 3.12.8:

| Observation | Result |
| --- | --- |
| Measured workload elapsed | 3.607 seconds |
| Root-read latency p50 / p95 | 6.436 / 10.587 ms |
| Mutation latency p50 / p95 | 11.416 / 22.763 ms |
| Server peak resident memory | 17136 KiB, about 16.7 MiB |
| Final redb file / JSON backup | 372736 / 320585 bytes |

These are client wall times for this loopback workload. Mutation latency includes
the destination-session check; plan preparation/fsync is excluded from individual
latency but included in elapsed time. They do not measure engine-only latency.
The server uses its default redb durability. The observed memory is not a general
worst-case bound; the test does not maximize every principal/query/schema shape.

An earlier run exposed avoidable client work: Python 3.12's default HTTP opener
initializes HTTPS trust roots even for plain HTTP. A small constructor probe
confirmed that cost. The client now constructs only the requested protocol
handler, retaining the standard HTTPS verifier. No connection/authority cache or
global mutable session was introduced. The earlier slow run is diagnostic
evidence, not a backend capacity comparison.

The [evidence](evidence/2026-10-22-d6-release.json) owns source/binary hashes,
exact commands, workload observations and the dependency audit. Local generated
artifacts stay under `target/`; source and tools build without original ReBase
or MetaSol runtime imports.

## Remaining capability gates

This release intentionally bounds source population and work; see the full
[resource envelope](../docs/deployment.md#supported-resource-envelope). Arbitrary
model authoring without engine edits, general decimal/rounding policies, full
accounting workflows, broader query paths, larger cascades, durable external
effects and distributed transaction conformance remain named future work.
Frontend is excluded. There is no claim of power-loss survival testing, sustained
throughput certification, public TLS-proxy deployment or multi-process failover.
Future tasks should enter the relevant gate, rather than repeat D1–D6 or port
every old API/tool unchanged.
