# Packet B: incremental subscription maintenance and capture ordering

Status: the B1/B2 native reproductions and the named D4 runtime/cost gates pass.
The failed full-group-repair candidate below is historical and was never
accepted. Production uses incremental membership repair plus the staged capture
boundary described in “Capture-order regression and repair.” The current bounded
acceptance results are in the [October 15 manifest](../evidence/2026-10-15-staged-capture-acceptance.json).

## Decision and evidence

The reviewed `d267dc2` added useful field-level patches, sequential mutation folds,
stable reader-identity cleanup, bounded candidate traversal, and tests. It also
added a final whole-group postorder repair. Its correctness rationale and cost
needed independent verification.

A native review counter measured 1, 4, 8 and 16 rebuilt nodes when adding the
corresponding subscriber to one shared group. Native EXPLAIN showed TableScan for
both `rebase_read WHERE group = ...` and `rebase_read_group WHERE tree_changed=true`.
The cost applied to ordinary new readers, not just unusual FX edits.

Before removing the workaround, the lead disabled only its postorder repair in
a disposable compiled bundle, retaining flag clearing and all original checks:

- Eight readers, each making two distinct reads in one helper's array expression:
  every completed transaction passed complete private-tree and expected-read checks.
- The full maintained FX regression passed 76 checkpoints, two rollbacks, both
  previously failing writes, and child-first cleanup without the repair.
- Full removal passed the generic observed-read suite: 50 checkpoints, seven
  rejections, concurrent registration, reapplication, and cleanup. It also passed
  the 64-reader cost control, but FAILED the accounting FX history.

The successful flag-retaining experiment does not establish that the rebuild is
redundant. Removing the mark writes, final group scan, final flag clear and flag
schema exposed a stale subtree. Ordering, stale images and runtime side effects
are hypotheses; causality is not isolated. Do not add a dummy write as a fix.

The full removal committed `sales_issue:f_late` but left a private subtree count
of **1** and last key belonging to `sales_issue:f`, while its live subtree contained
**2** entries including `sales_issue:f_late`. The group was
`[exchange_pair:widget_inr, '', 'record', 'effective_at']` — a record-read group.
The arithmetic model did not fail first; the structural checker failed after a
committed native transaction. This was not a rolled-back rejection.

The failing patch and raw log are in `../evidence/2026-10-15-remove-settlement-*`.
Full/minimized before/after snapshots for that candidate are in
`../evidence/2026-10-15-b1-full-first-divergence.json` and
`../evidence/2026-10-15-b1-minimized-snapshots.json`. The exact low-level
interleaving in the older external campaign was not directly traced.

## Capture-order regression and repair

The later full accounting run on revision `fccd847` found a different committed
divergence when creating `issue_adjustment:purchase` after its purchase issue,
original tax and advance settlement. The full acceptance state had a broken
parent link in the USD/INR `initial_rate` read tree. A purchase-only reduction
retained a dirty marker in the widget/INR latest-rate group. The complete SQL,
runtime identity and snapshots are preserved in
`../evidence/2026-10-15-capture-order-full-first-divergence.json` and
`../evidence/2026-10-15-capture-order-first-divergence.json`.

`fn::reads::remember` now stages a scope-keyed logical descriptor while a formula
evaluates. `fn::reads::flush` selects one scope through an index and reconciles
its reads in stable record-identity order. The refresh coordinator flushes
derived-field reads before updating the source, member reads before syncing its
trees, and required-output reads before publishing those outputs. Validation
reads flush before stale-generation cleanup. The transaction still owns formula
evaluation, source fences, registration changes and output writes, so failures
roll back together. Oracle checks require no stage rows after any completed
statement.

The committed acceptance records passing results for the full accounting suite,
multi-currency FX history, minimized purchase reproduction, seeded state histories
and bounded subscription-cost test after this change. The staged/unstaged
differential supports overlapping subscription mutations during captured formula
evaluation as the repair boundary. It does not prove the underlying engine cause
or identify the old native scheduler's exact instruction ordering. The accounting
model and read identities did not change.

## Failed settlement-removal candidate (historical)

The failed candidate removed these from `dev-tools/compiler`:

- `reads.surql:fn::reads::settle_group` and both writes of `tree_changed`.
- `temporal.surql:fn::tree::rebuild_subtree` and the global settlement loop.
- The generated `rebase_read_group.tree_changed` field.

That candidate left a stale subtree and was reverted at `7d722e4`. The subsequent
incremental repair removed the listed functions and `tree_changed` field again;
they are absent from the current compiler. The staged-capture path buffers logical read
descriptors and flushes them sequentially at explicit evaluation boundaries, as
described above. Its passing reproductions support that repair boundary without
tracing the engine's exact cause.

Invariants retained by the current implementation:

- Field-specific slot patches. A stale whole-slot write can overwrite a newer
  child, neighbour or parent link; do not reintroduce read/merge/replace patches.
- Sequential mutation folds and live-row loads between sibling refreshes.
- `insert/remove/change -> repair -> balance/rotate/pull`. Rotations pull the
  demoted node before its promoted parent; removal transplants links, not payload.
- Immediate publication after a private group's membership sync.
- Stable string reader-identity lookup after a business row is deleted.
- Typed logical query positions, point and interval indexes, consumed-value
  comparison, branch cleanup, source fences, and transaction rollback.

Use fresh disposable fixtures. No user database was changed by these experiments.

## B1: native reproductions and diagnosis (complete)

The original settlement-removal candidate and its failure are preserved in the
evidence listed above. Its arithmetic passed while a committed subscriber tree
summary was stale. The later current-runtime adjustment history was separately
captured before shutdown with its exact SQL, snapshots, SurrealDB/Node versions
and compiled bundle hash. The minimized failing state and the passing native
regression are `2026-10-15-capture-order-first-divergence.json` and
`dev-tools/accounting/capture-repro-probe.js`.

The first recorded divergence in that minimized history left a dirty key on the
widget/INR latest-rate subscriber tree after the adjustment committed. The full
accounting history also exposed a broken parent link in the USD/INR initial-rate
tree. The source formulas and independent read descriptions were unchanged by
the repair.
Buffering formula reads and reconciling them sequentially at the explicit
evaluation boundaries makes both histories pass. The differential supports
registration mutations overlapping captured formula evaluation as the repair
boundary; it does not prove the underlying engine cause or identify the exact
instruction schedule.

## B2: common repair and bounded cost (complete)

The private subscription tree stays incremental: inserts/removes repair affected
AVL ancestors, retained reads make no topology writes, and no whole-group
settlement pass remains. `rebase_read_stage` stores only transient logical read
descriptors, keyed by evaluation scope and read identity. Indexed scope selection
and sequential flush preserve source fences, generation cleanup, expected read
identity, rollback and publication order. Any failed source statement rolls its
staging rows back with the rest of the transaction.

The 64-reader insertion control needs six summary pulls; 48 range subscribers
need seven pulls. Retaining a query performs no topology repair. One and sixteen
matching ranges visit 22 and 38 interval nodes respectively, with one and sixteen
derived refreshes. Native EXPLAIN confirms source-group record-ID selection and
capture-scope index selection without a table scan. These are bounded structural
checks, not throughput measurements or asymptotic proof.

## Data structure and invariants

A business member is an intrusive slot on its source record. A slot stores owner,
parent, children, neighbours, typed key, leaf value, height and subtree summary.
An owning root stores root link, published summary and revision. Key order is
business components followed by record identity and slot; partial bounds sort
before their longer equal-prefix keys.

A logical read is a protected record identified by group, query position,
subscriber, phase and query fingerprint. The group identifies source record,
source slot, operation and projected channel. Point operations use `z_positions`;
ranges use `z_intervals`, augmented with maximum upper bounds. Neither dependency
identity nor observed meaning depends on rotations or the previously selected node.

Every completed structural sync must leave exact local links/heights/summaries
before another operation consumes them. For intervals, stale maximum upper bounds
can cause missed invalidations, so an eventual end-of-transaction repair is too
late as a general design rule. Public root publication is a separate phase from
repairing the live nodes used by private reads.

Prefix reads depend on every earlier contribution, even if one predecessor was
returned. Latest reads depend on selection plus the empty gap up to the reader.
Moves notify both old and new owners/positions. A reader moving along its own
history must not consume its old contribution. Keep `prepare_move` and its tests.

## Structural complexity targets and bounded gate (passed)

Let S be members of a source tree, R subscribers in one logical group, k candidate
reads, m executed distinct reads for one calculation, and w summary width.
These are structural targets, excluding result copying, SQL overhead and formulas:

| Work | Target |
| --- | --- |
| Source insert/delete/value change | O(w log S) repair work |
| New/removed private subscription | O(log R) ancestor work |
| Retained query with changed observed value | No topology repair |
| Latest/next candidate lookup | O(log S + log R + k) node visits |
| Rechecking those candidates | Commonly another O(k log S), plus formula/propagation work |
| Prefix invalidation | May genuinely reach every later reader |
| Interval stabbing | Conservative O(min(R, (k+1) log R)); do not claim O(log R+k) without proof |
| Evaluating/registering m calls | Query costs plus O(m log R), not a scan of all groups |

Building N ordinary subscriptions to one group should have O(N log N) structural
maintenance, instead of the former O(N²) rebuild work. Full cascade cost still
depends on the number of real dependencies, shared-fence contention, expression
cost, array copying, sorting and descendant writes. This is not a throughput claim.

`node dev-tools/temporal-tree/read-cost-probe.js` verifies the complete structure
and independent logical call set while inserting and deleting point readers,
inserting range readers in two groups, toggling a range branch, and checking
skewed fan-out. Its bounded insertion checks assert zero candidate lookups and
one derived refresh for each new reader; row deletion expects no candidate
lookups or refresh, while either active-branch toggle expects one refresh and no
candidate lookups. It counts actual summary pulls and node gets and confirms an
update retaining queries needs zero topology pulls. These are bounded structural
checks, not a proof of every asymptotic target or a throughput measurement. The
failed runtime candidate also passed a pull-count check at sizes 1,4,8,16,32,64
while still corrupting the accounting index, so a passing cost gate alone is
insufficient.

Do not replace typed AVL queries with native composite scans merely because the
fields look indexable. Earlier native record-ID ranges missed nanosecond boundaries.
A different native secondary-index design is possible only after demonstrating
correct typed order and indexed plans for all supported partial/composite bounds.

## If a new failing history appears

1. Save the first failing operation, seed, preceding source facts, complete state,
   actual compiled-bundle hash and engine version. Exclude harness setup failures.
2. Reduce it to the fewest logical reads/members that still fail with the common
   strengthened oracle. Check after each completed sync, not half a rotation.
3. Establish whether the fault is in the common AVL mutator, deleted-row frame,
   stale source image, caller evaluation order, invalidation bounds, or capture
   reconciliation. Do not infer a cause from the last thrown error alone.
4. Fix the common owner of the defect. Keep a failing-then-passing native case
   and a complexity gate in the same commit. Never add an accounting-specific
   repair hook or revive a full-group repair to make the final snapshot green.

Only if a native reproducer proves overlapping capture side effects corrupt an
otherwise correct serial AVL, consider staging logical reads and reconciling
memberships sequentially at an explicit evaluation boundary. First specify:
generation/deduplication, registration before dependent publication, cleanup of
old branches, nested required-output writes, validation phases, and source-fence
conflicts. Audit expression arguments, arrays, objects and map callbacks; changing
one map to fold does not prove every caller serial. Preserve atomic read capture
and reject unsupported mutating formula helpers. This is a conditional fallback,
not an instruction to build a new subsystem now.
