# G7 distributed storage adapter plan

**Status: G7 selected and implementation authorized, 2026-10-24.** G7.0
records preparation; later rows require their stated executable evidence before
acceptance. The accepted starting point remains source 0.15.0 and
[V1 verification](44-workshop-verification-result.md). This plan changes no
historical acceptance claims. FoundationDB is the first real distributed target;
redb and standalone SurrealKV follow. TiKV remains deferred.

## Goal and boundaries

Prove that the existing engine's atomic mutation and read contracts can run over
a real distributed transactional store. FoundationDB is the first real backend.
After it passes its own gate, compare redb and standalone SurrealKV 1.0 against
the same contract. This is adapter conformance, not a database benchmark or a
claim of production capacity.

Preserve business calculations and declaration meaning. Version/CAS/cursor and
storage API changes are permitted breaking changes and must carry explicit
identity/format revisions and acceptance evidence. Do not add an ORM, storage-specific business logic, or a new
query/model DSL. The engine owns byte codecs and semantic protection; adapters
translate point/range reads, guards, atomic writes, limits, and outcomes. The
FoundationDB path must use its native client and real SDK/runtime/network
lifecycle. Pin a compatible, stable FoundationDB Rust client/library pair and
record the exact client and server versions used by executable evidence.

The engine remains synchronous. Run it on a bounded blocking worker pool behind
the existing supported async boundary; first probe that bridge with the actual
client. Do not create nested Tokio runtimes or hide unbounded blocking calls in
async handlers. Keep one Cargo/build owner and reuse the repository's matching
caches. The coordinating owner controls shared files, `Cargo.toml`/lockfile,
runtime integration, checkpoints, and commits; contributors must stay within
assigned file boundaries. Preserve accepted evidence and historical artifacts.

## Contract to preserve

- An attempt has one consistent snapshot, exact point values and absences,
  read-your-writes, and an atomic all-or-nothing commit. A rejection or abort
  leaves every application table and receipt unchanged.
- Every read fact and predicate used for calculation or authority is protected
  through commit. Protection includes absent exact keys, uniqueness scopes,
  reverse-reference/dependency discovery, root invariants, and ranges. Range
  reads merge staged inserts, replacements, and tombstones; phantom insertions
  and deletions must conflict with affected predicates. Protecting a root means
  all edits capable of invalidating its invariant participate in the same
  protocol. Keep business-root coordination; a global lock is not a substitute.
- One commit atomically publishes **all application tables**: public/native
  records, all indexes and derived summaries, authority/session state, operation
  receipts, and effect intents/facts/inbox state where present. No partial table
  set or post-commit repair may stand in for this boundary.
- Reads use authorization consistent with their selected snapshot. Writes
  protect authorization and revocation state through commit. A response already
  authorized at its snapshot is not retracted by a later revocation.
- Do not automatically retry by default. An explicit confirmed conflict may be
  retried only by a later named policy that discards the entire attempt, cached
  authority and calculated patches, and uses a bounded fresh attempt. Unknown
  commit outcome remains unknown: reconcile the **original operation ID** and
  receipt before any decision to repeat; never mint a replacement ID or blindly
  resubmit. Surface backend time/size/key/value/transaction limits to the engine
  and reject an atomic operation that exceeds them.
- Keep operation, model, and codec identity checks. A changed model cannot
  reinterpret populated storage. No implicit migration is part of G7.

Before making scalability claims, explicitly remove the artificial global
revision and receipt hot keys. Replace them with tokenized or otherwise bounded
receipt coordination and scoped epochs/quotas over declared roots, with their
scope, limits, cleanup, and contention cost stated. Preserve per-business-root
coordination wherever an invariant requires it. If a safe replacement is not
ready, report the bottleneck and make no multiwriter scalability claim.

## Checkpoints and acceptance

Each checkpoint is a separate reviewable commit on the existing `main`, after
its checks pass. Record source/dependency/build identity, exact commands and
outcomes, backend/client/server versions, limits, evidence paths, and known
limits. Stop that checkpoint on any failed required check; do not continue by
marking missing evidence as a pass. A mock, conflict-set toy, or redb result
cannot substitute for a real FoundationDB schedule. Preserve earlier artifacts
and rerun only checks affected by a later change.

### G7.0 — contract and failure schedules

**Deliver:** finalize a compact adapter contract and deterministic schedule
specification before backend code. List every application table and protected
predicate; define point/range overlay behavior, snapshot authorization, commit
outcomes, explicit conflict handling, limits, and original-ID reconciliation.
Include barriers for absent-key uniqueness, range phantoms, root invariant,
reverse discovery/reference races, authority revocation, blind writes, no-op
guards, partial-write abort, lost commit response, and replay.

**Accept when:** an independent schedule oracle gives expected committed tables,
receipt presence/absence, and returned outcome for each interleaving; the
FoundationDB conflict ranges/guards that make each predicate safe are mapped.
This checkpoint establishes specifications only, not backend conformance.

### G7.1 — FoundationDB client and async bridge probe

**Deliver:** pin the stable FoundationDB Rust binding/native client pair and
document supported OS/runtime prerequisites, network setup/shutdown, cluster
file/configuration, transaction lifecycle, and version constraints. Probe real
point reads/writes, a tracked conflict read, async-to-bounded-blocking execution,
cancellation, and clean process/client lifecycle using a disposable local or
controlled cluster. Keep the probe isolated from engine mutations.

**Accept when:** the recorded client/server pair can initialize, execute and
shut down repeatedly through the production-chosen bridge; no nested runtime,
unbounded worker queue, or leaked client/network thread is observed. Record
measured limits and probe logs. If the bridge/client pair fails, stop and revise
the stack decision before G7.2.

### G7.2 — byte adapter and real transaction workspace

**Deliver:** implement the FoundationDB byte adapter and transaction workspace
for versioned engine keys: consistent point reads including absence,
read-your-writes, staged point writes/deletes, tracked protection, atomic
multi-key commit, abort, and normalized conflict/success/unknown outcomes.
Expose backend limits and diagnostics without changing business/API behavior.

**Accept when:** real FoundationDB transactions demonstrate old/new snapshot
visibility, atomic multi-key commit, abort after partial staged writes, conflict
classification, bounded limit rejection, and reopen/restart persistence. Every
failure leaves application data unchanged. Evidence names real database and
client versions and contains no mock-only claim.

### G7.3 — predicate protection and full engine publication

**Deliver:** implement exact-key and root guards, explicit half-open range
protection/overlay, and the shared mutation publication path over FoundationDB.
All application tables, indexes, authority state, receipts, and effect state
must use the same transaction. Keep codecs and settlement in the engine.

**Accept when:** G7.0 barrier schedules run against FoundationDB with controlled
concurrent transactions. Include absent uniqueness and range phantom insertion
and deletion; same-root invariant races; reverse discovery/reference races;
authority revocation; read-your-writes across staged ranges; no-op guard
protection; and forced failure after writes to each table family. Compare the
complete application-table inventory and receipt absence after every rejected
or aborted attempt. Run snapshot-authorized read controls. Any uncovered
predicate or partial publication blocks acceptance.

### G7.4 — operation outcomes, restart, and concurrency acceptance

**Deliver:** wire the ordinary engine/API path to the real FoundationDB adapter
with automatic retries disabled. Add explicit fault injection at request,
commit-response, and restart boundaries. Reconcile uncertain commits by the
original operation ID and receipt. Exercise bounded multi-client workloads
focused on correctness, contention, transaction limits, and root hotspots.

**Accept when:** a commit whose response is lost is reported unknown until the
same-ID receipt is read; reconciliation proves either committed result or
absence, and no replacement operation is submitted. Confirmed conflicts do not
silently retry. After process restart, accepted state and every table agree.
Record throughput/latency only as measurements of this setup, with load shape,
configuration, limits, and contention; no broad capacity claim follows.

### G7.5 — revision/receipt coordination and bounded scale claim

**Deliver:** remove the artificial global mutation revision and global receipt
hot keys. Introduce tokenized receipt allocation/reconciliation and scoped
epochs/quotas for declared roots, while preserving business-root guards. Define
bounded retention/cleanup and the exact atomic relationship to operation IDs,
receipts, and application changes.

**Accept when:** independent concurrent writers prove disjoint declared roots
can progress without a global serialization key; same-root invariant races
remain safe; retries/reconciliation retain original identity; quota exhaustion
and receipt cleanup are atomic and bounded. Report measured conflicts and hot
roots. If safe scoped coordination cannot be demonstrated, document the
remaining global bottleneck and defer scalability claims.

### G7.6 — cross-adapter conformance and closeout

**Deliver:** run a shared semantic conformance suite against FoundationDB,
existing redb, and standalone SurrealKV 1.0. For SurrealKV, use its documented
`get_for_update` protection where applicable, verify transaction behavior and
`Immediate` durability semantics, and add a range guard if point locking does
not protect phantoms. Treat it as a separately version-pinned adapter, not as
the SurrealDB query API. TiKV remains deferred pending its own isolation/client
review and exact protection design.

**Accept when:** all adapters pass the common contract cases each claims to
support, with backend-specific limitations explicit; the complete application
tables and receipts match after commit, abort, restart, and uncertain-outcome
reconciliation. Publish a concise result with hashes, exact named checks,
backend/dependency versions, runtime lifecycle, operational limits, contention
and unimplemented cases. Do not claim interchangeable behavior for unsupported
range or guard semantics.

## Deferred scope and references

TiKV, G6 accounting expansion, G8 workload/release expansion, frontend,
automatic retries, migration, arbitrary queries, and production-capacity claims
are outside this plan. Redb remains the accepted embedded deployment until a
separately accepted G7 result changes that statement. Preparation and this plan
do not mean implementation started or any database was executed.

Primary references to recheck when implementation is selected:

- [FoundationDB developer guide: conflict ranges](https://apple.github.io/foundationdb/developer-guide.html#how-foundationdb-detects-conflicts)
- [FoundationDB known limitations](https://apple.github.io/foundationdb/known-limitations.html)
- [FoundationDB Rust binding](https://github.com/foundationdb-rs/foundationdb-rs)
- [redb documentation](https://docs.rs/redb/4.4.0/redb/)
- [SurrealKV project](https://github.com/surrealdb/surrealkv) — verify the pinned 1.0 API and transaction guarantees against its versioned source/docs before coding.
- [Existing transaction and storage contract](02-transactions-and-storage.md)
