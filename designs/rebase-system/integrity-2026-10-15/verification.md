# Packet D: trustworthy histories and final acceptance

Status: OPEN. Run after B1 has preserved its failure; use this work to challenge B2,
not to justify a runtime repair from a few passing examples.

## D0: audit checker failure detection

The strengthened oracle now checks root neighbours and accepts nested record IDs.
Accounting expected-read inventory and exact decimal trees belong to A1/A2.
Before widening random histories, add valid controls and targeted corruptions for:

- Removing an entire subscriber/group/frame inventory without changing any values.
- Removing a required source fence while retaining its reads. Existing fence
  validation checks surviving fence rows; it does not yet require every captured
  source's fence to exist. Also check duplicate fence identities in synthetic input.
- Relocating a group to a wrong record identity while updating all links and
  retaining matching source/group fields. Reverse lookup relies on canonical ID
  prefixes; checking those fields alone may miss a self-consistent wrong address.
  Treat this as an audit target, not an already reproduced production failure.
- Wrong read fingerprint/identity, generation, active/inactive node slots, and
  root/leaf/neighbour defects for singleton and multi-node point/range trees.
- Tiny decimal corruption in leaf/subtree/root sum and both kinds of extrema.

Do not write another ad-hoc record-ID parser. Use native/SDK identity construction
or known identity maps with a declared serialization boundary. Never build the
expected dependency inventory from surviving metadata. Show that the untouched
control passes before claiming a corrupt variant is rejected for the right reason.

## D1: seeded logical-read histories

The existing seeded typed-tree campaign is useful but is **not** randomized testing
of the dependency registration/coordinator state machine. Extend the maintained
observed-read fixture/model; do not invent a generic testing DSL or duplicate the
production AVL algorithm as the expected model.

Use deterministic seeds (including 20261014, 7 and 1031), bounded operation counts,
and an independent sorted-source evaluator. Exercise:

- latest, next, before, exact, range, summary, and direct record reads;
- empty sources, insert-before-first, ties, full and partial bounds, inclusive
  flags, same-date nanoseconds, deletion and fallback restoration;
- source and reader date/owner movement, old/new source notifications, branch
  off/on, range resize, repeated identical reads, different projections/fallbacks;
- helper reads inside arrays, objects, nested calls, operands and maps, several
  siblings sharing a group, required output creation/deletion and publication;
- predecessor value unchanged, queried output unchanged, and changes to an
  unrelated measure. Count candidate and actual derived refresh work separately.

After each successful statement check business values, every node/root/thread,
exact expected logical reads, frames/fences, source references and exact sums.
After an expected rejection compare all relevant tables, including private
metadata and audit rows, canonically sorted by record identity. A committed
structural failure and a native rejection are distinct outcomes.

For a failing seed, save the **first** bad state, operation index, source SQL and
inputs, schema/bundle/source hashes, engine and Node versions. Minimize the
history before increasing iterations. Later writes healing an earlier defect
must not turn a failed campaign green.

Metamorphic histories: insert/delete an unused quote; move away/back; disable/
enable a reader; reparent away/back; reorder independent insertions. Compare
semantic source/derived states and independently reconstructed metadata; topology
shape and monotonically increasing versions need not be byte-identical.

## D2: closure and concurrency boundaries

Current direct self/two-record feedback tests do not prove every publication
cycle is detected. Build a changing loop through source posting -> published
root -> derived consumer -> source posting. Inspect whether finish's recursive
refresh resets active causal context. This is an open audit, not a confirmed
runtime failure. Require a useful bounded cycle rejection and full rollback;
a generic recursion/depth failure is not the intended public contract.

Include an acyclic diamond and legitimate strict-prefix calculations on a
reader's own history. A global ever-visited set would wrongly reject valid
revisits; distinguish active causal feedback from rescheduling and value changes.

Retain the existing concurrent first-registration/source-write race. Add empty
fallback registration, source insertion, owner move, and two competing edits.
Use controlled native scheduling only in fixtures; keep production free of sleeps.
A transaction conflict may retry the entire confirmed failed transaction. Check
the final state against the independent model and ensure no stale registration
commits. Do not claim distributed/multi-node coverage from one disposable server.

## D3: bounded performance gates

The intentionally red `read-cost-probe.js` must pass after B2. Extend it with
range subscriptions, branch churn, multiple groups and skewed fan-out. Count node
visits, summary pulls, and refreshes; inspect EXPLAIN for native selections.
One subscriber added to a large group must not rewrite all siblings or scan all
groups. Retaining a query should not alter topology.

State real limits: changing a prefix input may affect the whole suffix; candidate
comparison costs source queries; interval reporting has a conservative bound;
shared source fences create contention. Wall time of correctness fixtures is not
application throughput, and one fixed sample is not asymptotic proof.

## D4: final integration, once sources settle

Use fresh disposable SurrealKV databases. Rebuild artifacts before freshness
checks; ignored build files may be from a rejected experiment.

```bash
npm run test:dev-tools
npm run build:all-in-accounting
npm run build:all-in-one
npm run check:all-in-accounting
npm run check:all-in-one
surreal validate build/all-in-accounting/schema.surql
surreal validate build/all-in-one/schema.surql
npm run probe:compiler
npm run probe:architecture
npm run probe:derived-order
npm run probe:observed-reads
node dev-tools/temporal-tree/read-cost-probe.js
npm run probe:typed-tree-seeded
npm run probe:boundary-tree
npm run probe:required-outputs
npm run probe:causal-outputs
npm run probe:accounting-integrity-fx
npm run verify:accounting
git diff --check
```

Include the minimized B1 reproduction and D1's new seeded command as well.
Run permission/authentication gates affected by actual edits. Live provider,
frontend or unrelated network probes are not evidence for this engine repair.
Do not rerun the entire slow acceptance after every small edit. If a check fails,
fix the implicated packet, then repeat affected tests; record omissions plainly.

Publish one compact result with commands/status/counts, seed set, exact current
source hashes, actual compiled-bundle hash, versions, rollback scope, reapplication
and cleanup. Confirm every required table/root/read group/frame ends correctly.
Do not recycle October 14 counts or label an intentionally red gate as a pass.
The current FX harness embeds an October 14 evidence path in its command label;
replace that reporting constant with the actual invocation/output path. Do not
mistake a generated command label for proof that a command ran.

Commit D1-D3 tests separately from the final acceptance record. Update the entry
handoff's status only after the named gates pass on the final implementation.
Passing all these bounded gates still does not prove the absence of every bug.
