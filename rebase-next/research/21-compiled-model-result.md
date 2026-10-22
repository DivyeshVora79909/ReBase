# ReBase Next 0.3: compiled model reuse

**G1a–G1c accepted, 2026-10-22.** The engine checkpoint is `3b906a5`.
Two materially different native models now share the mutation engine, ordered
trees, causal settlement, authority, queries, receipts, storage lifecycle and
developer tools. Implementation remains inside `rebase-next/`.
[The goal](20-compiled-model-gate.md) and
[evidence](evidence/2026-10-22-g1-models.json) define this bounded acceptance.

## What changed

The original calculation model no longer fixes the shared record enum, derived
value type, schema-code range, tree slots, private-contract cutoff or count-array
layout. `NativeInput` supplies a model's own native bindings; `Binding` supplies
declarations, behavior, limits and independent checking. `Prepared<B>` validates
and prepares the selected declarations once, and `Store<B>` supplies the same
transaction, protocol and lifecycle implementation for that model.

`ReactiveBinding` resolves query/output shape from authored/direct inputs and
calculates amounts from ordered query values. Shared settlement collects affected
work, checks the final dependency graph, detaches old outputs, evaluates in
dependency order and reconciles fixed role identities. Ordered results cannot
discover new slots or topology. Schema/tenant/reference checks and exact generated
output tuple checks protect that boundary. One output currently has one financial
membership; arbitrary reactive monoids or a behavior scripting language are not
part of this gate.

Default calculation aliases keep the earlier proof concise. They do not select
another transaction implementation. Its independent Python oracles were adapted
only for explicit identity/format and count-map representation changes; arithmetic,
history and corruption obligations remain intact. The Equipment model owns
separate input/derived types and a source-only expected-state calculation, without
adding variants to the original enum or cases to shared business dispatch.

The binary selects `calculation` by default or `--model equipment` before the
command. The existing stateless client takes the model identity from its draft
and authenticated destination. Model schemas and declarations serve runtime,
catalogs, validation and fixtures. Trusted model callbacks remain ordinary Rust
with workspace access, rather than a sandbox for untrusted plugins.

Read [compiled model authoring](../docs/compiled-models.md),
[equipment usage](../docs/equipment.md) and
[the developer workflow](../docs/developer-tools.md).

## Independent second model

Equipment uses sparse public codes 101/205/410 and private code 900, availability
root 7, delivery/output member slots 17/23, query 31 and roles 11/29. A delivery
adds supply. An active reservation clips its request to availability strictly
before its start, consumes the allocation at its start and releases it at its end.
Its complete-time history must remain nonnegative.

Literal source expectations and actual ordered publications establish:

- Supply 10, A requests 8 over [10,30), B requests 7 over [20,40): **8/2**.
- Increasing supply to 12 gives **8/4**; moving A's end to 15 gives **8/7**.
- Deactivation/reactivation reuses role IDs; retargeting A to another pool with
  supply 6 produces A=6 and B=7. A zero allocation retains active query/output
  shape. Same-start over-allocation rejects rather than inventing an allocator.
- Invalid intervals, final historical deficits and private-output writes preserve
  state. Current authority, restricted new links, sparse-code pages/root reads,
  replay and graph revocation use the same outer implementation.
- Reopen and verified backup/restore preserve complete observations; a mismatched
  selected model and an earlier format header reject explicitly.

The model checker derives events, amounts and inventories from authored sources,
then shared checking verifies native rows, tree links/balance/neighbours/summaries,
routes, authority indexes, reservations and receipt structure. It does not replay
the settlement writer or trust cached tree queries as its source of truth.

## Executed acceptance

All **46 Rust tests** pass in debug and optimized release mode, with formatting
and warning-denying Clippy. New controls cover equipment lifecycle and real HTTP,
format-header rejection, resolved query-target enforcement and independently
checked model population limits. All **six client fault/TLS controls** pass.

The real native/local corpus runners and independent Python checkers pass again:
**68 foundation cases / 93 operations**, **39 causal cases / 55 operations** and
**nine local cases / 14 operations**. This includes complete state comparisons,
rejection rollback, reopening, causal diamonds, moved bounds and role lifecycle.
Their earlier dated evidence remains unchanged; current paths and fingerprints
are in this packet's evidence.

The optimized calculation HTTP harness passes two fixture instances, history
moves, archive fences, 64-source overflow rejection, duplicate/CAS races,
**128 writes and 1,024 overlapping reads**, crash/reopen and restored-service
checks. Final integrity is valid at revision 133 with 74 records, 14 nodes and
130 receipts. The optimized equipment CLI uses its explicit selector and the
unchanged client for durable plans, supply propagation, replay/status after
restart, wrong-model rejection and verified restore. Its final state is valid
at revision 2 with eight records, five nodes and two receipts.

This loopback calculation workload measured read p50/p95 **2.649/5.058 ms** and
mutation p50/p95 **3.249/10.132 ms**, with peak server RSS **16,732 KiB** on the
recorded Linux host. Mutation timing includes the destination session check;
plan preparation/fsync is outside each latency but inside workload elapsed time.
These observations establish this run, not a controlled performance comparison,
equipment throughput certification or capacity beyond the enforced envelope.

An isolated Git source archive builds with its explicit Cargo manifest and the
shared locked dependency cache, producing the identical optimized executable.
Its copied client passes all six controls and its copied harness passes the
workflow plus eight writes and 32 concurrent reads. No original ReBase runtime
imports or developer-workspace source paths are needed by that build.

## Explicit incompatible format

Release **0.3.0** uses `rebase-store-3` and `native-slice-kv-3`.
Calculation behavior is `rebase-calculation-contract-2`; equipment behavior is
`equipment-reservations-1`. Counts are a canonical schema-code map instead of the
old fixed array. Model identity covers explicit behavior and resolved declarations.
Store headers are checked before attempting to decode incompatible native data.

There is no silent format-2 migration. Keep an old release and its compatible
backups for old data, or initialize a new disposable store. Cross-model restore
is rejected. [Storage instructions](../docs/storage.md) describe this boundary.
No new dependency was added; the dependency-audit result from the preceding
release remains dated rather than being represented as a new audit here.

## Next capability gate

G1 is complete. **G2 is population and reactive-candidate capacity.** First fix
an increasing-population workload and independent correctness/work acceptance,
then implement and measure what it exposes. The current engine conservatively
opens subscriber sets and compares planned read/emission shapes pairwise; with
fixed slots this can be quadratic in affected producers. Structural checking
inventories the complete bounded store. Balanced tree paths alone do not make
every mutation logarithmic.

Both bundled models still enforce 64 public sources, 48 active outputs and
256 retained output reservations, plus separate command, principal, route,
receipt, transport, visit and work budgets. Do not remove constants and declare
large-scale support. Equipment's two outputs per active reservation can reach
its output cap first. An arbitrary valid-data generator, general aggregates and
rounding, full accounting, external effects and distributed adapter conformance
remain separate gates. Frontend remains excluded.
