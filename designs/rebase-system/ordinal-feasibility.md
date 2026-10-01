# Ordinal ordering: first implementation checkpoint

Status: historical checkpoint 1a passed on a disposable database, 2026-09-25.
The record below describes the original 1a change. **C1 is now complete** in
the [redesign plan](./plan.md), including compiled key/owner contracts, guarded
integer input and the versioned dual-order fixture. Fresh results are in
[verification](./verification.md). Statements below about an unchanged runtime
or future 1b/1c work refer to this historical checkpoint.
This is checkpoint 1a of the [system plan](./plan.md), not a compiled ordinal
feature or a completed business module.

## Recovered baseline

The checkout started clean at `cb2b64d` on `main`, six commits ahead of its
locally tracked `gitlab/main`. This is a local Git comparison; no remote fetch,
history rewrite, commit, or push is part of this checkpoint. `9581208` added the
accounting design; `cb2b64d` added the wider system design. Continue those plans
rather than creating another architecture.

The current profile has 22 root declarations. Accounting, CRM, HRM, billing,
logistics, manufacturing, and work planning remain distinct domains. Shared
identities do not create cross-domain calculation dependencies. The existing
module and tree catalogs remain the design baseline.

## Small steps and exit conditions

| Checkpoint | Work | Required evidence |
|---|---|---|
| 0 | Recover context and verify the current checkout. | Clean source baseline, current Node/SurrealDB versions, compiler checks and focused temporal regression. |
| **1a — this change** | Exercise integer order keys through the unchanged AVL runtime using a small handwritten fixture. | Independent source reconstruction agrees after rotations, duplicate ranks, edits, reparenting, omissions, deletion, and rejected writes. Numeric prefix/range/select queries agree. |
| 1b | Add explicit compiler contracts for temporal and integer-ordinal root/node slots. | Native strict types; incompatible modes, owner/slot routes, and malformed query boundaries fail closed; existing temporal output stays compatible. |
| 1c | Prove a versioned stage reference and a separate chronological history in a compiled fixture. | Consumed-field reactivity, domain isolation, permissions, concurrency, schema reapplication, and rollback pass. Only then enable an ordinal domain feature. |
| 2 | Resume temporal gates A/B, then required-output gates C/D in the [accounting plan](../all-in-accounting/plan.md#2-engine-feasibility-gates). | Each capability has a separate database proof before a module relies on it. |
| 3 | Implement one bounded module slice at a time using the existing catalog. | Named invariants, independent oracle, and whole-operation costs for each slice. |

This pass stops after 1a and records what it proved. Compiler integration is the
next separate change. This keeps the first experiment reviewable and avoids
combining key typing, timestamp policy, and output lifecycle in one patch.

## Ordering contract to preserve

1. **Two independent orders.** A chronological key remains
   `[effective_at, canonical_record_id, slot]`. The initial ordinal key is
   `[order_value, canonical_record_id, slot]`, with an integer first component.
   Do not encode a rating as a datetime or order integers lexicographically.
2. **One order domain per owner.** A domain owner binds the team/pipeline/skill
   and immutable scale version. Domain identity belongs in that partition; it
   is not a free sort-key prefix that allows unlike scales in one tree. The
   handwritten probe tests separate owners, not a complete scale model.
3. **Stable ties.** Equal order values are allowed across facts. Record identity
   and slot give deterministic order; neither insertion sequence nor mutable
   display labels break ties. Different ordinal codes do not imply distances.
4. **Missing values are explicit.** A fact with no selected order value does
   not join the ordinal tree. Setting/removing its value inserts/removes its
   slot. A domain that requires every fact to be ranked must require the source
   field instead; absence must never be silently mapped to zero.
5. **Order and measure differ.** Counts or compatible quantities may be
   aggregated in rank order. Do not sum/average ordinal codes as measurements.
   A timeline balance guarantee does not follow from an ordinal prefix.
6. **Read boundaries.** `[value]` is the lower bound before all ties. A full
   key can split a tie. Ranges are `[lower, upper)`, rank is a 1-based lower-bound
   insertion position, and select is 1-based with no result outside the tree.
   The prototype reads shared primitives directly; the compiled public API
   and mode-specific argument validation belong to 1b/1c.
7. **Mutation integrity.** Insert, amount edit, rekey, owner move, unranking,
   and delete preserve reciprocal links, AVL heights, ordered summaries, and
   clean publication state. A failed owner guard restores the complete source
   and tree snapshots, including revisions.
8. **Explicit limits.** The first mode uses integer ordinal codes. Decimal
   scores need a separate precision/finite-value contract and exact transport
   tests; full-width integer limits also need exact transport tests. The
   initial JS oracle deliberately uses small exact integers. Mutable global
   rank outputs and ordinal prefix-dependent formulas remain deferred.

Stage labels should remain stable typed identities in a versioned scale. A
later compiled fixture will derive each member's integer order from its stage
reference, while a separate temporal projection orders changes by effective
time. Reordering a populated scale must have an explicit version/migration
policy; this primitive experiment does not establish that lifecycle.

## Experiment boundary

The [fixture](../../dev-tools/temporal-tree/ordinal-fixture.surql) loads
[the shared runtime](../../src/temporal.surql) unchanged and
supplies only integer-key storage, simple membership adapters, and source
events in its disposable database. It has no reactive consumers. Its owner
count limit exists to test failure after maintenance, not to model a complete
CRM or HRM workflow. Internal fixture storage is flexible except for key
fields; it does not replace the compiler's complete generated schema or ACL.

The topology oracle reconstructs expected entries from authoritative fields
and scans them in numeric order. It does not call the membership adapter or
the runtime's combine function to compute expected summaries. The existing
temporal oracle remains datetime-based by default.

Passing this experiment supports reusing AVL maintenance and bounded summary
operations for homogeneous integer keys. It does **not** establish compiled
ordinal support, authentication policy, rank-dependent propagation, decimal
precision, mixed modes within a tree, interval semantics, or mandatory output
atomicity. It is a correctness experiment, not a throughput benchmark.

## Database input-coercion finding

On SurrealDB **3.2.0**, assigning `1.5dec` to an `option<int>` field aborts the
database process with `SIGABRT`. This was reproduced in a separate disposable
database containing only a plain table, with no ReBase functions or events:

```surql
DEFINE TABLE raw_input SCHEMAFULL;
DEFINE FIELD position ON raw_input TYPE option<int>;
CREATE raw_input:a SET position = 2;
UPDATE raw_input:a SET position = 1.5dec;
```

The server reported a panic in `val/value/convert/coerce.rs:717`:
`If can_coerce_to_kind returns true then coerce_to_kind must not error`, with
`InvalidKind { from: Number(Decimal(1.5)), into: "int" }`. Only reproduce this
case against a disposable server: the failure terminates that process.

The experiment's source input uses a native integer assertion before it can
reach integer-key storage:

```surql
DEFINE FIELD order_value ON ordinal_fact TYPE option<number>
    ASSERT $value = NONE OR type::is_int($value);
```

This accepts only native integers or absence and rejects fractional or
integral decimal-typed inputs without attempting the failing integer coercion.
The first key component is still stored as `int`. The standalone safe-input
case rejected `1.5dec` and preserved its original value; the main probe covers
rejected writes with populated trees. This is a tested fixture workaround,
not an upstream database fix or a patch to existing application schemas.

Compiler checkpoint 1b must carry this input boundary forward or verify a
database version with a corrected coercion path. It must also validate query
arguments before comparing keys. A successful AVL test does not close this
database input-safety requirement.

## Verification record

Environment: SurrealDB `3.2.0 for linux on x86_64`, Node `v22.23.2`, disposable
on-disk SurrealKV, fixed random seed `250925`. The probe creates its own
namespace/database and removes its temporary storage in `finally`; it does not
read application environment profiles or contact an existing database.

Run the bounded experiment with:

```bash
npm run probe:ordinal-tree
```

| Check | Method and coverage | Observed result |
|---|---|---|
| Numeric AVL maintenance | Integer source fields; LL/RR/LR/RL insertions; two-child and repeated root deletion; per-mutation source reconstruction of links, heights, summaries and publication state. | Passed within **111 mutation checkpoints**, including owner lifecycle. |
| Order semantics and queries | Negative/gapped codes, `2 < 10`, reversed insertion of tied IDs, missing ranks, short/full boundaries, empty/reversed ranges, lower-bound rank and 1-based selection. | **412 read assertions passed** against independent sorted/scanned sources. |
| Changes and owner isolation | Weight edits, rekeys, move between owners, rank removal/restoration, fixed-seed insert/edit/delete sequences. | Every resulting tree matched source reconstruction; unrelated owners remained unchanged during a rekey. |
| Failure atomicity | Over-limit create and move, lowering a populated owner's limit, invalid source/key types, and deletion of a referenced/nonempty owner. | **11 rejected operations** preserved complete source/owner/tree snapshots, including revisions. |
| Native input issue | Plain-table `option<int>` fractional-decimal reproduction without ReBase; separate guarded numeric-input check. | Raw case aborted the server. Guarded case rejected the input and retained the original record. No claim that the database bug is fixed. |
| Existing compiler baseline | `npm run check`; `npm run check:all-in-one`. | Both passed. All-in-one initially had stale ignored output; `npm run build:all-in-one` regenerated 49 tables / 0 views, then the check passed. |
| Existing temporal regression | `npm run probe:temporal-tree -- --quick`, including a run after the oracle gained an optional comparator. | Passed: 36 randomized mutations plus chronology, dependency, rollback, permission, concurrency, nanosecond/tie, and schema-reapplication cases. |
| Static validation | `node --check dev-tools/temporal-tree/ordinal-probe.js`; `surreal validate dev-tools/temporal-tree/ordinal-fixture.surql`; generated all-in-one schema validation. | Passed. |

The comparator option changes only the development oracle; temporal callers
retain the original comparator by default. No `src/` runtime or compiler file,
application schema, or existing regression expectation was changed. The full
application `npm run verify` matrix was not run for this fixture-only change.

**Historical next step at 1a:** checkpoint 1b, a separately reviewable compiler change. Specify the
root/node key-mode annotation, verify typed owner/slot compatibility, carry the
integer-input guard and read-argument validation forward, and preserve the
temporal baseline. Checkpoint 1a proves the shared mechanics for the tested
integer domain; phases 1b/1c and the temporal/output gates remain open.
