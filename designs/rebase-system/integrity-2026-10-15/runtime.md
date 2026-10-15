# Packet B: repair incremental subscription maintenance

Status: OPEN. Complete rebuild removal FAILED and was reverted. Production still
has whole-group settlement. The smaller passing controls below are insufficient
to remove it. Compiler and oracle fixes are separate.

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
Before/after database snapshots were not retained; obtain them in B1. The exact
first corrupting instruction in the older external campaign is also still unknown.

## Attempted removal, reverted

The failed candidate removed these from `dev-tools/compiler`; all are restored:

- `reads.surql:fn::reads::settle_group` and both writes of `tree_changed`.
- `temporal.surql:fn::tree::rebuild_subtree` and the global settlement loop.
- The generated `rebase_read_group.tree_changed` field.

Kept:

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

## B1: reproduce and isolate

Apply `../evidence/2026-10-15-remove-settlement-experiment.patch` in a disposable
worktree at this handoff revision, then run `node dev-tools/accounting/integrity-fx-probe.js`.
The patch is an experiment, not a fix. It includes the checker adjustment for the
absent flag. Supply dependencies in that worktree without changing application
configuration. Do not apply the experimental patch to the user's working branch.

Before rerunning, instrument the disposable harness to retain source SQL, the
actual compiled-bundle hash, engine version and full snapshots before/after each
source statement around the second sale. Save the failed committed state before
shutdown. A later repaired state cannot explain the first divergence.

Reduce the case from the three-currency setup, two sales invoices and two issues.
Remove unrelated dimensions/postings only while retaining the failure. A simple
one-query-per-reader control passed; the two-distinct-reads-in-an-array control
also passed. Preserve those as controls, not replacements for the failing case.

Prioritize one concrete hypothesis: the issue's stock and counterparty-resource
legs both value through `exchange_pair:widget_inr`, so one evaluation reaches
identical pair queries from several posting paths. The passing two-read control
used different fallbacks and therefore different registration IDs. Compare
identical versus distinct query signatures in the same scope, nested post calls
and concurrent expression operands. Trace INSERT IGNORE results, frame versions,
existing-read metadata UPDATEs and live node slots. This is a targeted experiment,
not an established cause; do not assume metadata-only UPDATE preserves slots
without checking its actual native before/after state.

Inspect completed remember/insert, sync, repair, rotation, pull, publication and
caller boundaries. Record live children and their summaries, summary written,
caller and phase. Find the first stale read/write. Audit argument, array, object
and map evaluation as well as explicit folds. Compare retaining just mark writes,
just the final scan, or just flag clearing only as controlled causal experiments.
Repeat the minimized failure to distinguish logic from scheduling sensitivity.

B1 exits with a small native reproduction and a specific causal explanation. If
that is unavailable, report an unresolved cause rather than a finished fix.

## B2: implement the common repair

Use the smallest correction identified by B1. Remove the rebuild and all its
bookkeeping only when the minimized case, accounting, generic reads and cost
gates pass together. An indexed dirty flag followed by a whole affected-group
scan still costs O(R); hiding a rebuild in publication is also unacceptable.
Commit B1 reproduction/evidence first and B2 implementation/tests separately.

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

## Required complexity contract (not yet met by production)

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

`node dev-tools/temporal-tree/read-cost-probe.js` creates a group up to 64 readers, verifies its
complete structure and independent logical call set, counts actual summary pulls
for insert/delete, and confirms an update retaining queries needs zero topology
pulls. This repair gate intentionally fails while whole-group settlement remains;
keep it out of the normal green suite until B2 is accepted. The failed runtime
candidate passed with 0,2,3,4,5,6 pulls at sizes 1,4,8,16,32,64 and still corrupted
the accounting index. A passing cost test alone is insufficient. Extend to
point/range branches and unrelated groups in the history packet. These are
bounded structural counts, not throughput measurements or asymptotic proof.

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
