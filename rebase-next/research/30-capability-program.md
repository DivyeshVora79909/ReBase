# Capability continuation after the 0.6 release

**Active program, 2026-10-23.** The user authorizes preparation, implementation,
verification and checkpoint commits on the existing `main`. The 0.6
[deployment result](29-deployment-result.md) remains accepted and dated. This
program preserves the original system's power, not its implementation or APIs.

## Intent and engineering boundaries

The available conversation and [source map](sources.md) establish the aim:
small explicit functions, one authoritative model shared by runtime and tools,
declared dependencies, exact calculations and predictable atomic publication.
Developers compose ordinary APIs; no new parser, universal DSL, plugin registry,
automatic read capture or separate workflow framework is required. Trusted Rust
models can break older APIs. New persisted meaning still needs an explicit
identity, complete checking and a defined incompatible-store response.

Do not replay every historical transcript or rerun accepted campaigns without
a changed obligation. Use current source and topic documents. Original ReBase
supplies semantics and counterexamples; it is not a runtime dependency.
All work and dependencies remain under `rebase-next/`. Frontend remains excluded.

## Capability map and dependency order

**Current execution boundary (2026-10-25):** V1 and G7 are accepted.
[The G7 closeout](51-storage-conformance-result.md) records real FoundationDB,
redb and standalone SurrealKV conformance through one persistence contract.
G8 implementation is active: [G8.0–G8.3 are accepted](53-workload-deployment-result.md);
G8.4–G8.5 remain to be accepted under [paper 52](52-workload-deployment-plan.md).
[G9 composable developer tooling](54-composable-developer-tools-plan.md) is
prepared, not implemented, for general population and reuse of workload tools.
TiKV, G6 and frontend remain deferred.
The last packaged release remains 0.6.0.

| Gate | Observable power | Preparation and acceptance boundary |
| --- | --- | --- |
| G4a | Validate a declared aggregate without a private output | Accepted: [terminal validation gate](31-terminal-validation.md) |
| G4b | Reactive time windows with two, one or zero bounds | Accepted: [exact windows and final-graph scheduling](32-reactive-windows.md) |
| G4c | Maintain a genuinely new summary/key contract | Accepted: [native index extension](34-native-index-extension.md), one active tree and dimensioned measurement statistics |
| G4d | Additional declared value dependencies | [G4d-a published-parent values](36-value-dependencies-gate.md), [G4d-b typed reports](41-native-query-consumer-result.md) and [G4d-c authored selection](42-authored-selection-result.md) accepted |
| G5 | Reliable external work | [G5a intent](37-atomic-intent-implementation.md), [G5b worker/application](38-fenced-worker-implementation.md) and [G5c inbox/recovery](39-ingress-recovery-implementation.md) accepted for the fixed fake provider |
| V1 | Self-explaining example verification suite | **Accepted:** [workshop result](44-workshop-verification-result.md), four non-accounting chapters, independent expectations, bounded exploration, replay and all 15 current capability rows |
| G6 | Representative accounting power | **Deferred until separately selected:** dated rational FX, sparse native/reporting contributions, resource/currency dimensions and quantity returns; existing bounded invoicing remains a regression example |
| G7 | Distributed storage | **Accepted:** [cross-adapter result](51-storage-conformance-result.md), FoundationDB/redb/SurrealKV; exact protection, coordination and HTTP-loss/restart limits recorded |
| G8 | Workload and deployment acceptance | **G8.0–G8.3 accepted; G8.4–G8.5 remaining:** [plan](52-workload-deployment-plan.md) and [results](53-workload-deployment-result.md), shared observations, churn, overload, owned database outage/recovery and current extracted release acceptance |
| G9 | Composable population and developer experiments | **Prepared, not implemented:** [G9.0–G9.4](54-composable-developer-tools-plan.md), authoritative metadata, typed reference pools, explicit runtime rules and existing workload/check reuse |

The table is the program, not a claim that every row is implementation-ready.
Close the next gate's semantic questions before coding it. Concrete examples
drive reusable primitives; avoid speculative scaffolding. G5 provider adapters
can proceed alongside G4 in separate files after agreeing lifecycle interfaces.
Atomic intent persistence and lifecycle operations require coordinated shared-core
integration. Distributed work does not block local business calculations.

Authentication protocols, audit retention, subscriptions, populated migrations
and large imports/exports are additional product choices, not silently supplied
by a KV adapter or the current JWT verifier. Bring them into a named gate when
required. Reuse supported protocol libraries rather than implement cryptography.

## Accepted window contract

Preserve timestamp groups, exact `i64` extremes and identity for empty/zero
queries. Use inclusive/exclusive/unbounded values without incrementing times or
synthesizing UUID sentinels. Sum windows may use group arithmetic; non-invertible
summaries require an ordered subtree fold.

Two implementation traps are identified from current source:

1. `Attempt::financial_impacts` and causal closure retain only the earliest time
   per root. General windows must retain all distinct old/new changed times:
   two disjoint windows can otherwise miss a change.
2. Prefix-gate dependencies cannot represent a bounded window: excluded earlier
   producers introduce false dependencies and false cycle failures. Preserve
   the efficient unbounded-prefix path and use exact canonical segment covers
   for bounded reads. Old/new routes discover work; the final graph determines
   evaluation order and feedback rejection.

Reuse the reverse AVL: upper endpoint ordering plus subtree minimum lower bound
is the dual of a lower-ordered/max-upper interval tree. Independently check every
augmentation and compare stabbing to literal membership. Charge work and report
conservative bounds: a historical change may affect many consumers.

## External-work preparation

[Transactions](02-transactions-and-storage.md#7-external-work),
[wireframes](07-contract-wireframes.md#8-external-work-and-future-capabilities)
and the original [operations design](../../designs/rebase-system/operations.md)
establish safety obligations. G5a-G5c now provide executable native evidence for
the bounded fake adapter; live providers remain separately scoped.

No irreversible provider call belongs inside an automatically retried mutation.
An intent commits with business state; a queue wake is disposable. Execution
identity and provider idempotency/reconciliation survive retries. An old backup
can resurrect work already performed remotely: restored dispatch must be
quarantined pending reconciliation, with a new worker activation fence and
unchanged execution/provider idempotency identity.

## Checkpoint discipline

Record contracts, independent acceptance, source/build identities, limits and
next action. Run formatting/Clippy before expensive optimized acceptance.
Preserve complete state and receipt absence on rejected writes, replay, reopening
and model/store identity. Commit and push each coherent checkpoint, then continue
without another prompt. Keep `CONTEXT.md` current for switching agents.

G4a, G4b, G4c, G4d-a/b/c and G5a-G5c are accepted. The
[G4d-c result](42-authored-selection-result.md) closes the previous selected scope.
V1.1–V1.5 are now [accepted](44-workshop-verification-result.md). G7 is subsequently
accepted above. G8 implementation is active with G8.0–G8.3 accepted and G8.4–G8.5
remaining; G9 is prepared only. TiKV, G6 and frontend remain deferred.
The [external integration review](35-external-integration-review.md)
locates G5's shared transaction and recovery seams. Atomic intent and bounded
fake-provider execution, durable signed ingress and restored reconciliation are
accepted. Later rows remain planned capabilities until their acceptance executes.
