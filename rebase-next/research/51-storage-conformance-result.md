# G7.6 cross-adapter conformance and closeout

**Accepted 2026-10-25. G7.0–G7.6 are complete within the recorded bounds.**
[Evidence](evidence/2026-10-25-g76-storage-conformance.json) records the exact
named cases, commands, hashes, dependencies and cleanup. This checkpoint uses
the unchanged source 0.16.0 accepted in [G7.5](50-scoped-coordination-result.md),
with store 10 /native codec 7 /effect codec 4 /API 4. It completes the
[adapter plan](45-storage-adapter-plan.md); the last packaged release is 0.6.0.

## Accepted matrix

| Adapter | Byte contract | Application /effects /predicates | Coordination /lifecycle | Secured HTTP races |
| --- | ---: | ---: | ---: | --- |
| FoundationDB | 25 | 19 +27 +12 =58 | 15 +14 =29 | 32 attempts; 8 commits, 24 confirmed conflicts |
| SurrealKV | 21 | 19 +27 +12 =58 | 15 +14 =29 | 32 attempts; 8 commits, 24 confirmed conflicts |
| redb | 8 | 13 +27 +9 =49 | 12 +10 =22 | 32 attempts; 8 commits, 12 stale-CAS and 12 invariant rejections |

Every listed case passes. FoundationDB's application, coordination and HTTP
results are reused from G7.5 after checking all 139 source/tool fingerprints.
The other rows and all three byte suites executed for G7.6 with the retained
matching binaries. There was no Cargo build and no repeated population, V1 or
accepted native campaign. The nine new commands took 21.574 seconds combined
in this local setup. A report-collection script initially treated the successful
SurrealKV HTTP wrapper's result path as a suite object; its eight successful
subprocess results were preserved, validated and followed only by the remaining
redb HTTP command. No backend control failed or required a repeat.

The byte oracle checks consistent snapshots, staged range overlays, atomic
publication and aborts across all six of its tables. Optimistic adapters also
run absence, insertion/deletion phantom, limited-range, table-clear, root,
no-op, reference and revocation schedules. FoundationDB adds four physical
limit controls. Its final 130-row byte image exactly matches SurrealKV's,
SHA-256 `e8cf3f75d8988e427495ebb088b112c99e1bb75df0c2059f9cd06c74b9aa40f0`.
redb's eight serialized cases produce their expected 116-row image; overlapping
native writer schedules do not apply to its blocking writer admission.

The application controls use real model calculations, materialized authority,
receipts, effect executions/facts/inbox and actual backend transactions. The
separate coordination oracle checks literal independent balances 8 and 7,
existing-record reference races, unchanged no-op reads, ABA, scoped cursors,
receipt collisions/final capacity and complete-digest archive races. Both
optimistic adapters pass the disjoint-root witness with no shared application
write, Meta/Population/header write, range scan or shared SurrealKV guard bucket.
The directly constructed 1,023-receipt fixture remains structural capacity
setup, not evidence of 1,023 executed operations.

Each HTTP workflow also accepts 13 ordinary operations and rejects 25. All
thirteen application tables survive rollback, application SIGKILL/restart and
fresh-target restore with exact per-store equality. Complete archive state is
preserved, contexts expire and reset changes store identity. Request/response
loss is reconciled with the original operation ID and saved context; no hidden
retry or replacement operation is submitted. A deliberately unsent request's
absent receipt does not establish the outcome of arbitrary in-flight work.

## Pinned behavior and operational bounds

The executed stack is FoundationDB client/server 7.3.77, Rust `foundationdb` and
`foundationdb-sys` 0.11.0, redb 4.4.0 and standalone SurrealKV 1.0.0, with Tokio
1.54.1, futures 0.3.32 and Rust 1.95.0 on Linux x86_64/glibc 2.39.
The engine owns codecs, calculations and guard meaning; adapters share one
persistence boundary and publish all application tables in one transaction.

- FoundationDB protects exact values/absences and the entire requested range,
  including portions beyond a returned page. Encoded keys allow 10,000 bytes,
  values 100,000 and transactions 10,000,000 including native conflict overhead.
  The adapter/client timeout is 4,500 ms; the advertised snapshot lifetime is
  approximately five seconds. Native network lifetime surrounds the command;
  engine work uses the existing bounded blocking workers. There is no retry loop.
- SurrealKV uses `get_for_update` for optimistic validation at commit and
  `Durability::Immediate` to request fsync. Each write updates one of 256
  per-table buckets selected by `SHA-256(key)[0]`; a scan validates all buckets
  for its table. Hash collisions and unrelated same-table writes can therefore
  conflict. A retained runtime drives the WAL, closes the tree and releases its
  directory lock. This is an embedded engine, not the SurrealDB query service.
- redb uses one blocking serialized writer, stable read snapshots and its
  default Immediate durability. Embedded adapters advertise no finite native
  limits through the common `Limits` structure; engine bounds still apply.
  Resource capacity beyond those checks is unmeasured.

HTTP timeout does not cancel an executing native transaction; its admission
permit remains held until work finishes. Exact population/reservation changes,
shared business roots, reader/contract epochs, occupied receipt probes and effect
runtime quotas remain coordination points. The local timings and one disjoint
existing-root witness establish no general throughput or capacity claim.

FoundationDB ran as one local process/coordinator without replication. The
remaining fault gaps are native commit-acknowledgment injection, database-server
or replicated-node failure, disk/power loss and real external-provider delivery.
HTTP proxy loss and application SIGKILL establish only their stated boundaries.
No migration, exactly-once external-effects promise or new release bundle is
included. See [backend operation](../docs/storage-backends.md).

## Checkpoint and stop boundary

G7.5 is local commit `86c61fe`. The user confirmed that local commits are enough
after HTTPS push credentials were unavailable; G7.6 is a separate evidence/docs
commit on the same `main`. The optimized executable and three probes remain in
`target/g75-accepted/`; the executable SHA-256 is
`288232e18700d24ef63c7db785f3aff51426a4c6e35b579a949f846d5a36b632`.
The G7.5 formatting, Clippy and default-feature checks remain applicable because
G7.6 changes no source/tool file. Changed documentation links and evidence
fingerprints are checked separately.

All owned application processes and the FoundationDB helper are stopped, its
listener is closed and no Cargo process remains. TiKV, G6 accounting, G8
workload/release expansion and frontend stay deferred. No further gate is
selected automatically.
