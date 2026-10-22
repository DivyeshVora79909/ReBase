# Deployable backend continuation

**Authorized 2026-10-22. Implementation in progress.** The user supersedes the
completed local-prototype goal. Continue autonomously, with coherent tested
checkpoint commits on the existing branch. Work stays inside `rebase-next/`.

## Goal and design rule

Deliver an operable backend and useful developer tools, excluding frontend.
Preserve the capabilities of connected facts, declared calculation, multiple
ordered memberships, historical invariants, private outputs and transactional
authority. Do not copy the SurrealDB implementation or promise compatibility.
One prepared model supplies validation and separate public/developer contracts.
Use ordinary Rust functions, explicit inputs and supported libraries. Extract
abstractions around actual uses rather than constructing a general framework.

A deployable release names its supported models, storage, transaction limits,
identity boundary and operational envelope. A deployable bounded release does
not establish full accounting parity or distributed scalability. Keep remaining
capability gates visible instead of silently calling every feature production.

## Implementation checkpoints

| Checkpoint | Required result | Status |
| --- | --- | --- |
| D1 | Shared goal and continuation, existing evidence preserved | Complete |
| D2 | Fresh transaction-scoped principal/DAG authority, separate owner/reader, complete indexed readable candidates; independently checked repair and rejection | Complete |
| D3 | Authenticated bounded network API using the same ordinary operations; shutdown, limits, receipt/replay and revocation exercised over the wire | Complete |
| D4 | Storage lifecycle: explicit model/format identity, safe backup/restore, reset of owned disposable state, integrity and recovery checks | Complete |
| D5 | Model-driven developer workflow and repeatable valid fixture scenario through public operations; no raw fixture writes | Complete |
| D6 | Workload and deployment acceptance: release build, concurrency, restart, documented resource envelope and runnable deployment instructions | Next |

Each checkpoint closes a concrete semantic boundary before expansion. Change
the sequence when implementation provides a better dependency order; record why.
Use independent expected results for new semantic boundaries, keep historical
dated evidence intact, and rerun the existing native/local corpora when engine
or persistence semantics change. Tests must verify behavior, not copy algorithms.

## Starting inventory and later capability gates

The [local result](16-local-prototype-result.md) is independently verified at
`4393be2`: 27 Rust tests, original/causal native corpora, local receipt checker,
formatting/Clippy and a fresh isolated archive build/demo. It contains actual
native settlement and linked trees, not just tooling.

The current compiled twelve-contract model is intentionally bounded. D2–D6
must not turn those bounds into an unqualified capacity claim. Broader model
authoring without engine edits, general money/rounding, full accounting workflow,
additional ordered access paths, durable external effects and distributed
adapter conformance remain named capability gates. Use the existing
[research workflow](08-research-workflow.md), [model design](04-implementation.md)
and [lifecycle contract](07-contract-wireframes.md) when entering each gate.
Frontend can consume generated public contracts later; it is excluded now.

The first storage target is one supported embedded redb process, with serialized
writers and concurrent snapshot readers. Do not claim a generic get/put trait
provides distributed transaction conformance. Keep protocol/identity separate
from the calculation core and keep all persisted administration in the same
atomic transaction boundary as the state it governs.

## D2 decisions to implement and test

- One tenant per embedded store. Principals have immutable UUIDs and kinds;
  parent edits are tenant-local and reject cycles. Alternate DAG paths survive
  edge deletion. Direct tenant/group parent access does not expose siblings.
- Cryptographic authentication supplies an actor identity; each operation loads
  its current authority from its data transaction. A token never supplies its
  own trusted permission graph. Graph administration is a separate operation.
- Client writes/new links use current authority. Internal declared recalculation
  uses tenant-scoped engine authority. Never require the actor to edit every
  indirectly recalculated fact.
- Preserve the ordered scalar-reader fold; declaration-marked references select
  immediate owners. Analytics/private maintenance cannot grant new visibility.
  Repair dependent readers and candidate indexes atomically on policy changes.
- Readable pages merge disjoint reader partitions in UUID order. Complete scope
  initialization has a cap; candidate visits have a separate budget. Cursors
  bind actor/model/store/query/revision. Missing/inaccessible point IDs have the
  same public answer. A budget-limited existence result stays unknown.
- Preserve rollback, private contracts and exact scalar transport. New public
  errors must not leak hidden operands or storage details.

## Continuation record

D1: established the new user goal and preserved the distinction between the
completed local experiment and production capability acceptance. No runtime
behavior or historical evidence changed in this checkpoint.

D2: implemented ordinary pure graph/scope functions in `access`, the embedded
authority adapter in `security`, and per-operation actor sessions on the existing
store. Domain repair now uses tenant-scoped engine authority, while authored
commands/new links use the freshly loaded scope. Managed outputs retain their
producer's owner. Declaration-marked references choose immediate-owner readers.
Graph replacement atomically repairs readers and disjoint reader/contract/UUID
indexes; requests merge only permitted partitions. Normal writes point-load
cached dominance sets rather than rebuilding the graph. Graph edits use explicit
compare-and-set administration; disabled identities are retained, credential
epochs cannot decrease, and reactivation requires a new epoch.

Acceptance: 31 Rust tests, formatting and warning-free Clippy; the existing 68
foundation, 39 causal and nine local-adapter cases still pass their independent
checkers. New checks exhaust 64 small DAGs against an independent parent walk,
exercise alternate paths, group scope, divergent owner/reader, reader repair,
credential revocation, actor-scoped receipts, disclosure suppression, cursor
invalidation, unchanged rejection, physical abort and reopen. Complete privileged
observations include authority and reader tables. No network authentication or
capacity claim is made by D2. [Evidence](evidence/2026-10-22-d2-authority.json).

D3: implemented HTTP `/rpc` with Axum/Tokio, reusing strict stdio JSON-RPC
dispatch. Ed25519 JWT identity is verified by jsonwebtoken/AWS-LC, separately
from current per-operation DAG authority. An offline trusted issuer helper and
`session.describe` complete the operator/client boundary. The
[server guide](../docs/server.md) fixes the profile, rotation, network limits,
TLS ingress, and lost-response semantics. No inspector/raw writer/issuer RPC
endpoint exists. A deadline retains admission for unfinished blocking work;
SIGINT/SIGTERM drain accepted work.

Acceptance: 34 Rust tests, formatting and warning-free Clippy. Real HTTP checks
prove one application under eight concurrent identical receipts, one winner
under eight stale-version contenders, current epoch revocation, bounded bodies,
unknown methods and reopening. A held-writer deadline control proves the request
can commit after its response times out, while its permit remains occupied.
The selected lockfile passes cargo-audit 0.22.2 against 1348 current advisories,
with zero vulnerabilities/warnings. Trial RustCrypto selection pulled unpatched
RSA; AWS-LC removes that dependency. D3 adds no capacity or accounting-parity
claim. [Evidence](evidence/2026-10-22-d3-network.json).

D4: added a complete current-state verifier, consistent private backups, checked
temporary-file restore with atomic no-clobber publication, and an atomic reset
that revokes old credentials/cursors/operation contexts. An explicit behavior
revision replaces the prototype's source/dependency-bytes-as-data-identity rule.
Store format 2 intentionally rejects old prototype data. Maintainers bump the
behavior contract for semantic changes; evidence still fingerprints execution.

Receipt retention now has an operator archive and a cryptographic generation
fence. Mutations/status require the original `context` from `session.describe`;
old uncertain requests cannot silently reapply after their receipts are archived.
The backup is durable before its receipt window is cleared. This was an actual
release blocker found during lifecycle work, rather than an automatic eviction
policy. [The lifecycle guide](../docs/storage.md) owns these operational rules.

Acceptance: 38 Rust tests, formatting and warning-free Clippy; foundation/causal/
local independent corpora pass after explicit identity/header/context updates.
The new checker runs on every complete local-adapter observation and does not
call writer/rotation/settlement/query code. More than 20 deliberate corruption
controls reject; damaged/incomplete/duplicate-key backups publish no destination.
Verified restore matches all tables; reset preserves principals and rejects old
credentials; archive rejects old request replay and permits offline reconciliation
from its restored receipt snapshot. Historical receipt truth, automatic migrations,
large exports and distributed recovery are not claimed.
[Evidence](evidence/2026-10-22-d4-lifecycle.json).

D5: added offline fixture planning from the design-owned recipe, standard UUIDv5
namespace binding and typed reference remapping through prepared declarations.
The public catalog stays separate; the developer catalog lists available recipes.
The existing local demo now uses the same recipe loader and authored expectations.
One standard-library Python client supplies ordinary RPC calls and durable JSON
plans with explicit endpoint/model/store/tenant/actor binding. Plans contain no
credentials and retain the original operation context through replay/status.
No fixture RPC or alternate native writer was added. See the
[developer workflow](../docs/developer-tools.md).

Acceptance: 39 Rust tests and warning-free Clippy; five independent client wire
controls; a real HTTP harness with two namespaced fixtures, three committed
operations, six expected rejections, exact 150-to-100 report change, restart
replay/status, obsolete receipt-projection suppression and archive expiry. A
truncated Content-Length control exposed and fixed response framing in the client.
The current-state verifier passes after restart and archive. Model identity is
unchanged; no engine/binder/codec/persistence behavior changed and the earlier
native corpora were not rerun for this tooling-only boundary.
[Evidence](evidence/2026-10-22-d5-tools.json).
