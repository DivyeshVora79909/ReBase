# Integrity repair handoff — October 15, 2026

The acceptance at `3ee5205` recorded passes for the named D0 and D2–D4 gates.
D1's seeded history campaign remains partial: it does not cover dated logical
readers, required-output lifecycles or expected-rejection histories. Those
seeded combinations remain deferred. This is bounded
native-engine acceptance, not a claim that every possible history is bug-free.
The final command list, runtime, source fingerprints and compiled accounting
bundle hash for `3ee5205` are in the [acceptance manifest](../evidence/2026-10-15-staged-capture-acceptance.json).
The [review follow-up](../evidence/2026-10-16-review-fixes.json) records the later
compiler guard, mandatory canonical-ID checks, and focused verification.

| Packet | Result | Main implementation |
| --- | --- | --- |
| C: local field ordering | Complete | `95d7197` |
| A: independent accounting inventory and exact tree math | Complete | `66846dd`, `704eb66` |
| B: incremental read-tree repair | Complete for the bounded gates | `6b7d3c1`, `f705eac`, plus the staged-capture repair described in [runtime.md](runtime.md) |
| D: corruption controls, observed histories and acceptance | D0 and D2–D4 bounded gates pass; remaining seeded D1 combinations deferred | `631c92c`, `fccd847`, final acceptance manifest |

The prior full-group repair candidate was rejected after it committed a stale
subscriber subtree. The retained B2 implementation repairs memberships
incrementally; the 64-reader and 48-range structural cost checks now pass.

A later full accounting run exposed a second committed defect while creating a
purchase issue adjustment after its issue, original tax and advance settlement.
The full history had a broken `usd_inr` read-tree parent link. A purchase-only
reduction retained a dirty marker on a `widget_inr` latest-rate group. The full
before/after snapshots and compiled-bundle identity are preserved in the
[full divergence](../evidence/2026-10-15-capture-order-full-first-divergence.json)
and [minimized divergence](../evidence/2026-10-15-capture-order-first-divergence.json).

The runtime now buffers logical read descriptors during formula evaluation, then
flushes one registration at a time at explicit refresh and validation
boundaries. Refresh reads flush before derived source updates, member repair and
managed-output publication. The independent expected-read inventory remains
unchanged. A dedicated [native regression](../../../dev-tools/accounting/capture-repro-probe.js)
and the committed acceptance record cover this history; no staging rows survive
a completed statement or cleanup. The differential supports registration
mutations interleaving with captured formula evaluation as the repair boundary,
though the exact internal SurrealDB cause and scheduling sequence were not
directly instrumented. Treat this as a repair boundary supported by the
differential, not a traced first failing instruction.

## Recorded staged-capture acceptance (`3ee5205`)

- Full accounting acceptance: 103 source-oracle checkpoints, 51 full rollback
  snapshots, populated-schema reapplication and child-first cleanup.
- Multi-currency integrity history: 76 per-write checkpoints, two exact rollback
  snapshots and cleanup; includes dated FX, account currencies, adjustments,
  taxes and tax-on-tax.
- Minimized purchase capture regression: seven structural/source checkpoints,
  exact amounts and empty staging after cleanup.
- Observed-read suite: 50 checkpoints, eight rejections, concurrent registration
  and source-write conflict reapplication.
- Seeded observed histories: seeds `20261014`, `7`, and `1031`; 216 checkpoints,
  489 candidate reads and 196 derived refreshes. The campaign uses integer point
  keys; the nanosecond quote fixture is unused by its readers. The remaining
  combined D1 cases listed above are deferred; separate deterministic fixtures
  cover portions of date, rejection and output behavior.
- Bounded cost gate: a 64-reader insertion used six summary pulls, zero candidate
  lookups and one refresh; 48 range subscribers used seven pulls. Sixteen matching
  ranges visited 38 interval nodes and refreshed 16 readers. Both group and
  capture-scope selections avoided table scans.
- Typed trees: 252 mutation checkpoints, 1,570 ordered reads and 108 rollback
  snapshots. Boundary algebra: 4,665 timestamp/delta sequences and 777
  missing-measure sequences. Required-output and causal-output cycle/rollback
  checks passed.
- Both accounting and all-in-one builds, freshness checks, SurrealQL validation,
  compiler and architecture checks passed. The developer suite passed 48 tests.

## Scope and limits

The recorded acceptance uses disposable SurrealKV on one local SurrealDB 3.3.0
server with Node v24.19.0; the independent fresh review subset used Node v22.23.2.
These checks do not measure production throughput, prove multi-node behavior,
test a live application database, or prove absence of all bugs. Prefix edits may
refresh a real suffix, candidate comparisons still query source values, and
shared source fences can contend.

Preserve sparse currency/resource dimensions, native stock quantities,
event-time FX, opposing receivable/payable entries, combined adjustment math and
chronological tax order. Invoices validate participating postings without
reposting their children. No accounting equations changed in this repair.
