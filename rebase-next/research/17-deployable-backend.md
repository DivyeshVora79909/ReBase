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
| D2 | Fresh transaction-scoped principal/DAG authority, separate owner/reader, complete indexed readable candidates; independently checked repair and rejection | Next |
| D3 | Authenticated bounded network API using the same ordinary operations; shutdown, limits, receipt/replay and revocation exercised over the wire | Pending |
| D4 | Storage lifecycle: explicit model/format identity, safe backup/restore, reset of owned disposable state, integrity and recovery checks | Pending |
| D5 | Model-driven developer workflow and repeatable valid fixture scenario through public operations; no raw fixture writes | Pending |
| D6 | Workload and deployment acceptance: release build, concurrency, restart, documented resource envelope and runnable deployment instructions | Pending |

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
