# Compact context — 2026-10-21

## Purpose and authority

ReBase is a calculation engine for connected, typed facts. The redesign changes
the implementation stack while preserving its mathematical and domain concepts.
The objective is the smallest amount of complex behavior the developer must own:
explicit contracts, composable functions, predictable work and narrow boundaries
that prevent maintenance changes from spreading across unrelated components.

The latest user corrections in the attachment take precedence over earlier
suggestions. Current source takes precedence over historical agent reports.
Sources, fingerprints and topic locations are in [sources.md](research/sources.md).
The baseline is ReBase `a963b25`; MetaSol is a separate repository at `28c6e7f`.
GitHub was checked and already current. GitLab pull failed for missing credentials.

## Meaning to preserve

1. **One stable record identity.** A fact can own roots, contribute through
   multiple slots, consume inputs and validate state. These roles are independent.
   A record can also have no tree role. Physical database tables are optional.
2. **A contract defines obligations.** Strict fields, allowed reference targets,
   immutable dimensions, required participation, calculations and invariants must
   be unambiguous. A compact schema code is the proposed selector; a full class
   hierarchy in a key is unnecessary. Sparse records and selected dimensions do
   not require all possible dimension combinations.
3. **References and memberships are distinct.** A currency reference does not
   imply a currency index. An invoice may validate children without reposting
   their amounts. A payment's contract can require treasury participation.
4. **A root is an ordered projection and publication boundary.** Its identity is
   `(owner record, root slot)`. A member is `(source record, member slot)` with a
   typed business key and deterministic tie breakers. One source may appear in
   several roots or several positions in the same root.
5. **Fixed-width associative summaries maintain rules efficiently.** Count,
   sum, extrema, ordered prefixes, complete-time boundaries, tags and interval
   endpoints are examples. Ordered combination need not commute or have inverses.
   Exact units, nanoseconds, rounding and missing-value semantics are contractual.
6. **Dependencies are declared.** Local fields follow actual dependency order;
   direct referenced fields use reverse routes; ordered reads declare source root,
   operation, bounds, consumed channel and fallback. Slots are fixed by the model;
   record inputs can change their activation, source and bounds.
7. **One dynamic principal DAG.** Tenant, user and group ancestry handles control
   and sharing. Domain reference graphs may have diamonds; each maintained index
   has tree topology, and active calculations must remain causally acyclic. These
   are different graphs, not a restriction that all business relations are trees.
8. **Access and calculation authority differ.** Requested writes and new links
   require client authority. Declared internal repairs and protected derived
   outputs use engine authority. Neither bypasses tenant or invariant checks.
9. **Retain the reader distinction.** The final discussion retracts removing
   `read_by`. Read visibility uses a selected immediate reader principal; write
   authority uses `owned_by`. Reader indexes must enumerate readable candidates.
10. **Execute against one transaction attempt.** Read a consistent snapshot,
    cache touched state, stage changes, settle dependencies, validate and commit
    final dirty values atomically. Retries discard the entire attempt and its
    authorization cache. Raw KV writes bypass the engine's guarantees.
11. **Effects have durable intent.** External delivery follows commit. Inline
    waiting and background dispatch can share the same intent/lifecycle; a due
    time supplies one-shot scheduling. Pure signing grants are a separate case.
12. **Declarations serve tools too.** Publish input schemas and operation
    contracts; derive inspection metadata and supported access paths from the same
    loaded model. Keep fixture recipes and appearance/workflow choices explicit.

## Corrections already resolved by the discussion and contracts

| Phrase or hypothesis | Precise meaning |
| --- | --- |
| Compiler becomes runtime | Load and validate declarations once; execute their prepared plans in Rust instead of generated SurrealQL. Compilation and runtime coexist. |
| Current writes commit repeatedly | Current synchronous events run inside an atomic transaction. They issue incremental maintenance statements; the redesign proposes a shared workspace and fewer final dirty writes. |
| Segment/rank/statistics tree are identical | An augmented balanced search tree supplies overlapping capabilities. Median amount needs amount ordering; date ordering supplies date rank. |
| Everything is `O(log n)` | Each balanced path is logarithmic; affected records, memberships, intervals, partitions and DAG closure add work. |
| Monoids remove validation | They preserve enough information to make a declared invariant cheap to check. A nonnegative final sum does not prove a nonnegative history. |
| Validate after every rotation | Check structural conditions immediately; business rules at a settled checkpoint or the final atomic-operation boundary. Incomplete construction can be temporarily invalid. |
| Shared blind write normalizes OCC | A portable guard must have a defined conflict contract, normally a tracked read plus changed write. FoundationDB does not reject concurrent blind writes solely for sharing a key. |
| Stateless token includes a wrapper | Token proves identity and may narrow capabilities. Server-owned plans enforce current authority. Client wrappers cannot enforce a boundary. |
| Request cache solves every revocation issue | Read current permissions in each attempt; protect those reads against concurrent edits. Session revocation remains a separate policy. |
| Owner partitions cover all reads | False when `read_by != owned_by`. Retain reader partitioning or another complete reader candidate source. |
| K-way merge everywhere | Use it only for several streams sharing the same full order. A single root needs one traversal. |
| UUID includes tenant/owner/hierarchy | Keep mutable relationships out of canonical identity. Store a schema code and relations in the record/header; roots provide partitions. |
| Deterministic short hash means unique code | A persisted explicit codebook supplies stable uniqueness. A seed cannot losslessly compress arbitrary growing identities. |
| JSON is necessarily the bottleneck | Parse/validate at ingress, compute using native values and encode at egress/persistence. Profile before claiming a dominant cost. |
| Any ACID backend is interchangeable | Atomic multi-key commit, consistent reads, guard semantics and limits must conform. Raw write batches alone are insufficient. |

## Proposed smallest architecture

Use one Cargo package and ordinary modules. One loaded design combines unchanged
JSON Schemas with separate declarations for references, memberships, queries,
invariants and exposed operations. Ordinary trusted Rust functions supply behavior.
Do not invent a general query language, dependency capture framework, universal
middleware DSL or one package per feature.

Rust is the recommended execution core; Serde and `serde_json` handle values;
`jsonschema` compiles reusable validators. `jsonrpsee` plus Tokio can host the
eventual JSON-RPC server; Axum/Tower is optional when broader HTTP routes are
needed. Start storage proof with redb's ordinary serialized writer transactions.
FoundationDB is the proposed distributed adapter, conditional on conformance and
transaction budgets. TiKV and other engines are alternatives, not promised support.

Use stable 16-byte UUIDs and explicit `u16` schema/field/slot codes. Random UUIDv4
matches the latest observation that identity need not order records; UUIDv7 is
available for locality. Leave shorter custom IDs and principal dictionaries until
measurements justify their allocation/collision costs. Keep business payload and
structural slot storage separate without creating another business identity.

Public operations are structured `get`, `page`, `exists`, `mutate` and declared
root reads. An explicit mutation is one atomic unit; a JSON-RPC batch is not.
Queries select registered access paths, typed bounds, allowed predicates and
projections. Unsupported orderings reject. Optional residual filtering has a
visit budget and continuation; exhausted-budget `exists` is **unknown**.

## Important choices still open

- The new mutation API should default to final settled global validation. Declare
  independent command checkpoints explicitly; this changes current per-statement
  acceptance semantics. Early failure must be conclusive, not a transient deficit.
- Preserve current ordered scalar-reader selection initially. Its first-choice
  rule for incomparable principals is deliberate and is not a union or a universal
  lowest node. Multi-reader sharing requires a separately chosen policy.
- Start linked augmented indexes for the required mathematical operations.
  Ordinary ordered KV prefixes may implement simple enumeration later; they must
  not become undeclared default domain indexes or dictate the portable core.
- Exact decimal range/rounding, timestamp range, public cursor change policy and
  large-cascade rejection budgets need explicit production decisions.
- Distributed adapters, cryptographic identity verification, full graph repair,
  full dependency settlement and external-effect delivery are outside this proof.

## Work completed and continuation boundary

The [feasibility report](research/05-feasibility.md) records the executable Rust
checks and their scope. Standard AVL balance, heap merge and identity mathematics
are established algorithms; their proofs need no broad stress campaign here.
Unusual complete-time summary composition and transactional staging receive
focused checks against independent expectations.

Next: implement **one** runtime mutation slice with a source, two memberships,
one direct dependency, one dated query and one invariant. Compare settled state
and bounded work against source recomputation. Add a distributed adapter only
after protecting reads, absences and reverse-discovery predicates correctly.
Performance claims require profiling this slice; current SurrealDB acceptance
and historical LMDB experiments are source evidence, not Rust-runtime benchmarks.
