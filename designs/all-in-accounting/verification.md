# Accounting verification — 2026-10-07

This is historical acceptance. See [October 8 extension verification](extension-verification.md) for current sources.

The subsequent [reader/index change](../rebase-system/reader-index-verification.md)
updates the shared framework and reruns accounting regression. The original
accounting redesign evidence below remains tied to commit `88c5ae7` and its
recorded hashes; it does not imply the shared framework stayed unchanged later.


Local acceptance passed against the final October 7 sources. The
[acceptance record](../rebase-system/evidence/2026-10-07-accounting-redesign-acceptance.json)
contains commands, results, source and generated-artifact SHA-256 hashes, and
the comparison with the saved shared-engine baseline.

## Commands and results

| Command | Result |
|---|---|
| `npm run build:all-in-accounting` | Passed: 51 tables, 17 materials, 0 views; ten domain source files and 34 public create schemas |
| `npm run verify:accounting` | Passed in 397.33 seconds: current generated output, native schema validation, 63 mutation checkpoints and 35 complete rejection snapshots |
| `npm run test:dev-tools` | Passed: 27 tests, 0 failures, 4.05 seconds; includes the 15 client-schema tests |
| `npm run check` and `npm run check:all-in-one` | Passed: generated output current |
| `npm run probe:compiler` and `npm run probe:architecture` | Passed: compiler contracts, determinism, validation, authorization and synchronous rollback boundaries |
| `node --check` on the three accounting JavaScript files | Passed |
| `git diff --check` | Passed |

The [accounting transcript](../rebase-system/evidence/2026-10-07-accounting-redesign-verify-output.txt),
[developer-tool transcript](../rebase-system/evidence/2026-10-07-accounting-redesign-tests-output.txt),
and [architecture transcript](../rebase-system/evidence/2026-10-07-accounting-redesign-architecture-output.txt)
retain the actual output. The final accounting run includes the invoice dimension
and claim-family guards. Runtime: Node `v22.23.2`, SurrealDB `3.3.0`, disposable
SurrealKV storage. The example prepares eleven native SDK records without
opening a database connection.

## What passed

- Direct accounts, shared stock-account uniqueness, required invoice ancestry,
  covered advances and invoice-date rollback.
- Strictly earlier net-tax readers, equal-time parallel taxes, backdated
  recalculation, bounded marginal tax rules, and old/new ancestor repair.
- Return/refund versus adjustment dates, physical stock reversals, signed
  quantity/price/FX changes and linked adjustment-tax reactivity.
- Purchase direction, withholding, currency conversion, exact rounding and an
  explicit split-return remainder.
- Future production, gross simultaneous inputs, treasury reservations, service
  windows, output capacity, parent rescheduling and adjacent half-open capacity.
- Independent competing sessions, authenticated source writes, cross-tenant
  rejection and exact native SDK decimal binding. A supplied computed issue
  amount of 999 is replaced by the correct VALUE result of 1.
- Exact domain/audit equality after identical schema reapplication to populated
  data, followed by explicit child-first deletion and empty account histories.

Every mutation checkpoint replays authored inputs with independent rational
arithmetic and reconstructs tree membership, topology, chronology and summaries.
Derived financial fields use exact comparisons; the existing structural oracle
retains its numerical tolerances for tree summaries. Rejection snapshots compare
all 34 domain tables and `audit_mutation` before and after the failed operation.
The 34 public exports are byte-identical to their authored JSON schemas, and
all remaining package-script targets and changed documentation links resolve.

## Scope

All 67 saved compiler/framework/gateway/config files match the pre-change hashes;
those shared implementation directories have no Git diff. The focused engine
checks above passed during this task; the full repository `npm run verify` suite
was not repeated. Historical October 5 and H1–H8 results retain their original
source snapshots and do not certify this redesigned API.

This is local functional acceptance. The timing includes schema setup,
independent snapshots, reapplication and cleanup; it is not a throughput or
physical-storage capacity measurement. A populated conversion from the old
schema, deployment, live providers and the separate MetaSol frontend migration
are outside this acceptance. Tax children, bills of materials, yield and legal
tax policies remain explicitly authored business choices.
