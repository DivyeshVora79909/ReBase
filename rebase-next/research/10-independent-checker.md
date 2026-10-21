# M6: independent state and structural checking

**Status: bounded checker contract and executed controls, 2026-10-22.** This follows the
[M3/M5 causal packet](09-causal-settlement.md). The experiment checks deliberately
assembled snapshots; it does not add a tree writer, storage adapter or runtime.

## 1. What a successful check means

A successful check needs three independent agreements:

1. The observed authored facts match the intended accepted commands or the named
   fixture. Otherwise a source and every consequence could disappear together.
2. Those facts and the authored contract imply exactly the observed calculated
   values, active outputs, memberships, query descriptors and reverse slots.
3. Actual links form valid indexes over that complete population, with exact
   cached summaries and no pending settlement work.

A structure walk alone cannot establish population completeness. A comparison
of totals cannot establish either population or structure. A checker that
derives its expected queries from surviving descriptors will accept their
complete disappearance. A checker that discovers roots only by inspecting
surviving root-shaped objects can miss a required empty root.

The current [dependency oracle](../../dev-tools/temporal-tree/dependency-oracle.js)
already accepts source-derived expected queries, requires declared roots, and
keeps descriptor/result/index obligations separate. The
[structural checker](../../dev-tools/temporal-tree/oracle.js) checks tree order,
balance, height, reachability and neighbours. Its general demonstration numeric
comparison allows tolerance; the
[exact checker](../../dev-tools/temporal-tree/exact-oracle.js) separately scans
source contributions using exact decimal arithmetic. The current
[dependency probe](../../dev-tools/temporal-tree/dependencies-probe.js) composes
those checks. These are inspected current sources, not newly executed suites.

The historical [checker review](../../designs/rebase-system/integrity-2026-10-15/verification.md)
records missing-inventory controls and its own scope limits. It describes an
older captured-read implementation; its frame/generation structures are not new
requirements for the declared-query design. Preserve the failure lesson without
copying the superseded machinery.

## 2. Inputs, independence and snapshot coverage

| Input | Authority and purpose |
| --- | --- |
| Fixture or confirmed-command facts | Independent expected source population, identities, authored values and successful/rejected operation boundary. Never reconstructed from derived fields. |
| Authored declarations and ordinary reference formulas | Allowed source/root/slot types, activation, coalescing, queries, lifecycle and invariants. The tiny oracle spells out these rules independently of a production prepared plan. |
| Complete raw snapshot for a named scope/model | Actual facts, calculated fields, managed outputs, descriptors, node slots and root headers, including disconnected private nodes. One consistent snapshot, not sequential unrelated reads. |
| Observation provenance | Model/codec identity and a coverage guarantee supplied by the test harness/adapter. A database field saying “complete” cannot certify its own scan. |

The first native slice must retain a source oracle outside its maintenance code.
It may share exact scalar types, but must not call the runtime's membership
provider, dependency planner, summary combiner or discovery indexes to decide
what should exist. If a prepared plan omits a slot, both runtime and checker must
not inherit the same omission. Explicit literal expectations and corruption
controls anchor the small independent model.

Without a separate command/fixture history, checking raw facts against their
derived state establishes calculation integrity only. It cannot prove a missing
source was never lost or that an acknowledged command was applied. Unknown
commit outcomes remain unknown until the operation-receipt contract resolves
them; do not add such a command to the expected accepted history speculatively.

Do not obtain the actual population by traversing only known roots or by using
the indexes being checked. Enumerate the complete declared private namespaces
in a bounded disposable store. Check raw identity multiplicity before building
maps; duplicate rows must fail instead of being silently deduplicated. Reject
malformed or undeclared entries rather than skipping objects that do not look
like valid nodes. Exact UUID/key decoding belongs to the snapshot adapter;
[paper 12](12-native-slice.md) now supplies the bounded native version.

Results distinguish **valid**, **invalid with an obligation/identity**, and
**incomplete**. A truncated scope, exhausted verification budget or snapshot
that cannot be held consistently is incomplete, never valid. Whole-store audit
may require offline/exported state; it is not necessarily possible inside one
distributed transaction. The bounded experiment receives complete in-memory
images and checks explicit incomplete-scope/budget controls; it cannot prove a
real scan's completeness or consistency.

The checker call requires an explicit completeness assertion from that harness;
there is no default that silently certifies an arbitrary supplied image. Missing
the required argument is an interface error; a declared partial scope produces
the incomplete result tested below.

## 3. Expected state before traversing actual nodes

Build the expected inventories exclusively from the first two inputs above.

| Inventory | Required comparison |
| --- | --- |
| Authored records | Exact identity multiplicity, contract and authored fields; include fixed fixture roots, seeds and bases. |
| Derived values and managed outputs | Exact values and required `(source, role)` population; no extra private outputs or duplicate identity. Inactive output reservations, when implemented, have a distinct persisted lifecycle obligation. |
| Root headers | Every declared root for every expected owner, including empty reverse roots. No unknown root slots. |
| Financial membership slots | Exact source/slot identity, root, full key and payload. Apply only the declared financial coalescing rule. Zero contributions remain members. |
| Named queries | Exact identity, activation, operation, phase, root, typed bounds, channel, fallback and independently computed result. Equal bounds/results do not merge identities. |
| Reverse query slots | Exact population and source root derived from those expected queries. Compare endpoint metadata even when amounts and lower keys do not change. |
| Other reverse routes | Direct-field dependencies and reference/delete registrations must also be source-derived when the first native slice adds them; this range-query experiment does not implement them. |

An inactive query has no active descriptor or reverse slot. An active empty
range still has a descriptor/result but need not have an interval node under
the chosen contract. `latest` depends on its declared logical root/bound, not
merely the row that answered it. These distinctions must be reflected in the
expected inventory; the current experiment uses only active nonempty ranges.

Use set equality **and** uniqueness/multiplicity checks. A count alone cannot
distinguish a missing node from an unrelated extra node. An owner reference is
not evidence that its required membership was installed.

## 4. Checking a tree independently of its shape

For every declared root, compare actual node inventory before traversing it.
Walk actual child links with a visited set and a bounded work counter. The
verifier may trust none of the stored height/count/summary fields to decide
where to stop or what population to expect.

1. Every root/child link resolves to an existing node in the expected root.
   Reject cycles, shared children and cross-root links. The root node's parent
   uses the declared root-parent convention; every child points back to its
   actual parent.
2. Lower/upper bounds enforce the complete typed key, including source/slot tie
   breakers. A locally sorted pair is insufficient for a deeper subtree.
3. Recompute heights from child structure, then check cached heights and AVL
   balance. A perfectly summarized but unbalanced search tree still fails.
4. The visited node identities equal the full expected node set for that root.
   Also compare all observed private slots globally so disconnected extras fail.
5. Derive previous/next neighbours and root endpoints from the complete sorted
   occurrence sequence. Require reciprocal exact links and empty endpoints for
   an empty root; do not use the neighbour chain to define expected membership.
6. Recompute every subtree's declared summary from its source-expected leaves,
   and the published root summary from the complete source-expected sequence.
   Do not combine cached child summaries or compare two equally corrupted caches.

Any valid balanced shape passes. The checker does not prescribe a median root,
rotation history or a canonical byte layout. Research images use `parent = None`
for a root node; this is a normalization for the fixture, not the existing
SurrealDB root-parent encoding or a chosen persistence codec.

Exact financial scans include count, first/last full keys, sum, record-prefix
extrema, completed-time extrema, and optional internal completed-time boundary
extrema. Group all equal timestamps before checking complete-time balances.
Absent internal boundaries remain absent, not zero. Interval scans include
count, first/last keys and maximum upper endpoint. Use typed infinities:
`negative infinity < before_time(t) < positive infinity`; no timestamp arithmetic
or greatest-UUID sentinel. The empty interval summary has maximum endpoint
negative infinity. This convention is explicit and need not become wire syntax.

Every declared field is checked exactly, including its scalar type. Python's
`True == 1` or `10.0 == 10` must not turn malformed values into valid exact
integers. Sparse channels and general decimal/composite codecs need their own
binding checks when added; no numeric tolerance is introduced here.

A simple raw scan for every subtree costs `O(n log n)` on a valid balanced tree
and can do more work before rejecting a damaged one. That is acceptable for a
tiny independent checker. Its work budget prevents a damaged graph from causing
unbounded verification. This is not a claim about mutation complexity or a
proposal to scan a populated production store on each write.

The experiment's work counter counts observed rows, visited nodes and leaves
examined by raw summary scans. It excludes preparation of the fixed source oracle
and does not measure CPU instructions, allocations, transport or storage reads.
The baseline uses 55 observed rows, 15 node visits and 40 scanned leaves: 110
such work units. This is a reproducible checker limit, not a runtime benchmark.

## 5. Bounded snapshot and corruption controls

Reuse [M3/M5's source oracle](experiments/m3_m5.py), unchanged. It has no tree
maintenance code. The [M6 experiment](experiments/m6.py) builds synthetic link
layouts from that expected population, then checks and corrupts copies. Sharing
the source oracle here does not rerun the 36 M3/M5 orders or implement settlement.

The baseline contains 12 authored fixture records, five calculated values,
five managed outputs, eight named queries, seven financial nodes, eight reverse
interval nodes, and ten root headers. The reverse roots of B and final are empty
but required. Changing tree shape cannot change any logical inventory.

Positive controls cover two valid balanced layouts, a zero-valued posting,
disabled output with surviving queries, and deletion of P with its query slots
legitimately absent. Literal scans also distinguish same-time cancellation from
a historical deficit. These controls prevent “reject everything” or one-shape
comparison from masquerading as verification.

The negative controls isolate the following obligations:

| Change to a previously valid image | Why totals or a local check could miss it |
| --- | --- |
| Erase every A reverse descriptor/node and reset that reverse root to empty | The remaining reverse structure is self-consistent; source expectations still require six queries. |
| Remove a declared empty reverse root | No leaf traversal reaches it. |
| Duplicate a raw identity or add a disconnected private node | Map construction or a root-only walk could hide the problem. |
| Remove a zero contribution and rebuild its smaller tree | Financial sums and query answers remain equal. |
| Change query phase or bound while retaining the answer | Dependency/validation meaning changes without a numeric change. |
| Change two leaf amounts by opposite deltas and rebuild caches | The published total is conserved while the authored formulas are violated. |
| Break parent, child, neighbour or root endpoint/link | Financial payloads remain correct. |
| Create a cycle/shared child or a valid but unbalanced BST | Cached sums do not certify traversability, order or balance. |
| Corrupt an internal cache, published cache or interval maximum | Root-only comparison or trusted pruning can skip the damaged obligation. |
| Leave pending work or use a floating cached integer | A superficially equal result is not a settled, typed state. |
| Supply a consistently calculated history with a negative completed-time balance | Structural consistency does not imply business validity. |
| Withhold complete scope or exhaust the checker budget | Missing evidence must be incomplete rather than accepted. |

The run accepted all five valid controls, rejected all 28 invalid-state controls,
and reported both partial-scope and exhausted-budget controls as incomplete.
Controls record the specific failing obligation, not just an arbitrary exception.
The [evidence](evidence/2026-10-22-m6.json) records executed results, snapshot
fingerprints, work counts and source hashes. No live database was corrupted.

## 6. Acceptance boundary and next work

This packet closes the independent checker contract for the bounded M scenario
and executes its logical/structural corruption controls. It does not establish
the correctness of a native AVL writer, incremental query discovery, direct
reverse routes, UUID allocation, snapshot export, API permissions, receipts,
rollback or distributed conflict protection. That packet left the Rust proof
unchanged; this Python checker is a research oracle, not a runtime dependency.

The [native implementation plan](11-native-slice-plan.md) now fixes paper 8's
simpler M1/M2/M4 commands, exact state, source oracle obligations and rejection
snapshots. [Paper 12](12-native-slice.md) now records S1–S5 execution. Its native
summary caches hold times, while this synthetic image holds full-key endpoints;
the adapter must check actual stored fields and full order separately, without
inventing cache fields. Bounded direct/reference/subscriber lists also require
new source-derived expectations; those inventories and the real raw adapter
have now passed the native cases. The original synthetic evidence above is
unchanged and makes no claim for a native M3/M5 writer.

M3/M5 supplies later causal counterexamples; it does not force private outputs or
general prefix settlement into the first slice. General query-driven topology,
full APIs/dev tools and distributed adapters retain their own gates. The plan
uses the M contracts without claiming every scenario capability is accepted.
