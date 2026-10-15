# Integrity repair: lead entry point, October 15

Start here, then read only the packet being executed. This supersedes the October
14 completion claim. **The engine is not fully accepted.**

| Packet | Status | Commit / instructions |
| --- | --- | --- |
| C: local field ordering | Bounded fix complete; unsupported row flows reject compilation | 95d7197, [compiler.md](compiler.md) |
| A: oracle/accounting | Root threads and nested source IDs fixed; expected accounting reads and exact aggregates OPEN | 66e87d0, [accounting.md](accounting.md) |
| B: incremental index repair | OPEN; unsafe simplification reverted; failure preserved | 33ad46f, [runtime.md](runtime.md) |
| D: broader verification | OPEN | [verification.md](verification.md) |

The compiler preserves literal argument positions and rejects whole-row aliases
and wrappers it cannot analyse. Direct declared helpers and explicit scalar
arguments retain automatic ordering. The oracle now checks root neighbours and
accepts nested source record IDs. Accounting equations were not changed.

Production retains the d267dc2 tree/read runtime. Complete settlement removal
passed smaller/general probes but committed a stale subtree at the second sales
issue in the FX fixture. It was reverted. The experimental patch is not a fix.

Fresh current-runtime FX acceptance passed **76 checkpoints, two full rollback
checks and cleanup**. The new cost diagnostic intentionally fails at **11 readers:
16 summary pulls exceed its allowance of 15**. Both correctness and complexity
must pass; neither result cancels the other.

## Aim and scope

The user wants a declarative engine: write formulas, typed reference relationships,
memberships and constraints once, then automatically maintain supported logical
dependencies in the source transaction. Latest reads watch a value and the gap
where a new predecessor can appear. Prefix reads depend on earlier aggregates.
Branches, dates, owners, empty results, fallbacks, deletes and rotations must work.

Preserve sparse accounting dimensions, native quantities, dated FX, nonnegative
opposing receivable/payable entries, combined adjustments and chronological taxes.
Invoices validate participating facts without reposting children or enforcing
compliance workflows.

Breaking changes are permitted; the project is undeployed. Prefer one correct
common implementation with a documented supported language. Do not restore
authored impact rules, add accounting-specific repair hooks or move synchronous
closure into gateway background jobs. Frontend, new business modules, rootless
trees and storage-engine replacement are outside this repair.

## Assessment of the lower-model changes

d267dc2 added 1,690 lines and removed 262. Additions: 208 compiler/runtime,
944 tests/tooling, 538 docs/evidence. Line count alone does not establish fragility.
Preserve useful fixes and fixtures. Concrete problems were:

- Helper analysis accepted expressions that silently committed old derived values.
- Whole-group settlement made ordinary subscription growth cost O(N²) structural
  work and used two full-table scans.
- The private oracle skipped root neighbour links.
- Accounting validated surviving reads, without proving required reads existed.
- Exact derived-amount arithmetic still fed Number-based, tolerant tree checks.
- Seeded typed-tree coverage was not a seeded logical-dependency state campaign.

Some completion claims exceeded their evidence. Inspect code, Git and negative
controls; neither trust reports blindly nor revert the entire commit indiscriminately.

## Next-model execution order

1. Read runtime.md and reproduce B1 in a disposable worktree. Preserve the first
   failing native state and isolate causality before choosing a redesign.
2. Implement A1's independent accounting call inventory and A2's exact tree values
   as separate commits. They can be developed independently of B1.
3. Implement the smallest common B2 correction justified by that evidence. Both
   the accounting history and red cost gate must pass. Staged capture is a
   conditional alternative, not an instruction to build a new subsystem.
4. Complete D's checker controls, logical histories, closure/concurrency tests and
   final integration. Record actual source and compiled-bundle hashes.
5. Update status honestly. A healthy final snapshot cannot erase an earlier failure.

The lead completed the bounded compiler/oracle fixes. Remaining runtime diagnosis
and independent model work exceed the requested short-fix scope. Keep commits per
packet; use small reproducers while editing, then one final slow acceptance.
If several focused experiments cannot isolate a cause, hand back the first
divergence and a narrow question instead of adding a speculative repair layer.

## Evidence and continuity

- [Current FX result](../evidence/2026-10-15-lead-fx.json)
- [Lead verification manifest](../evidence/2026-10-15-lead-review.json)
- [Failed complete removal](../evidence/2026-10-15-remove-settlement-failure.txt)
- [Experimental patch](../evidence/2026-10-15-remove-settlement-experiment.patch)
- [Flag-retaining control](../evidence/2026-10-15-flag-only-control.txt)
- [Current cost failure](../evidence/2026-10-15-current-runtime-cost.txt)
- [Original helper error](../evidence/2026-10-15-original-helper-failure.txt)
- [Historical user context and original stress-report interpretation](../integrity-repair-handoff-2026-10-14.md)

The external /workspace/accounting-lab campaign is unavailable here. Maintained
fixtures and committed experiments are local executable evidence; do not claim
the external campaign was rerun. Full consolidated accounting was not rerun in
this lead turn. A fresh FX pass does not replace A or D.

Commits are local. No application database, .env, remote service or deployment was
changed. Check Git status and preserve intervening work. Do not infer remote
publication authorization from an older agent's handoff prose.
