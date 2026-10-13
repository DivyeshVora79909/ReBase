# Accounting verification — October 13

Fresh consolidated acceptance passed on SurrealDB 3.3.0 / Node 22.23.2 with
disposable SurrealKV: **101 source-oracle checkpoints and 51 rejected-write
rollback snapshots**. Core and extension cases ran together in one database,
followed by exact populated-schema reapplication and child-first cleanup.

The [developer guide](developer-guide.md) defines the accepted API. The
[machine-readable evidence](../rebase-system/evidence/2026-10-13-subsidiary-accounting.json)
records cases, timings, the schema fingerprint and all 71 frozen authoring/probe
source fingerprints. The
[acceptance output](../rebase-system/evidence/2026-10-13-subsidiary-accounting-output.txt)
records the completed run. Earlier October 7/8 evidence retains its historical
source and API scope.

## What passed

- Sparse subsidiary/native positions, multiple treasuries, units and mirrored
  counterparty contributions without invoice or note reposting.
- Covered advances and chronological linear invoice capacities; product-difference
  quantity/price adjustments and nonnegative directional receivable/payable entries.
- All five strict tax-adjustment tables, direct rule propagation, dated bases,
  marginal capped rules and prevention of duplicated tax effects.
- Dated-rate insertion, edits, moves, reparenting, deletion, fallback and reader
  date/reference changes; native stock quantities stay intact during valuation edits.
- Independent rational source replay and declared AVL/link/summary verification
  after mutations, plus rejected-write comparisons of accounting and audit snapshots.
- Inline fees and fee taxes, withholding, tax cash/offset capacities, monetary and
  resource claims, competing settlements, transfers and separate exchange observations.
- Native production reservations, strictly prior gross-input funding, output
  capacity, resource windows, adjacent intervals and rejected overlapping capacity.
- Tenant isolation, protected computed/tree fields, native SDK decimals, the
  executed 17-record fixture and its forward/inverse graph and tree queries.
- Identical populated reapplication preserves the accounting and audit snapshot.
  Sequential child-first deletion leaves financial, reader and observation roots
  empty and structurally valid; descriptor/account indexes remain valid.

All **27 developer-tool tests** passed; see the
[test output](../rebase-system/evidence/2026-10-13-subsidiary-accounting-dev-tests.txt).
Compiler and architecture probes passed. All 48 client-schema exports match their
sources, and all 374 exposed business fields are authored inputs. The CLI and
acceptance probe use the same 8,634,177-byte schema. Supporting checks are in the
[check log](../rebase-system/evidence/2026-10-13-subsidiary-accounting-supporting-checks.txt).

The function-impact primitive is separately committed at `6ffac15` and its
focused probe passed again during this acceptance. Its
[original evidence](../rebase-system/evidence/2026-10-13-function-impact.json)
covers 13 checkpoints and six rollback snapshots, exact bounded candidates,
overlap deduplication, unchanged-output suppression, moves, deletion/fallback,
cycle/tenant rejection, reapplication and cleanup.

## Observed acceptance cost

| Phase | Elapsed |
| --- | ---: |
| Fresh schema application | 308.846 s |
| Fixture setup | 7.799 s |
| Core and extension scenarios | 1,414.216 s |
| Populated schema reapplication | 570.685 s |
| Sequential cleanup and final checks | 306.772 s |

The complete run took approximately 43.5 minutes on this host. These are one-run
correctness-suite timings, including source scans, structural checks and repeated
DDL. They do not measure ordinary transaction latency or production capacity.

## Reproduce and continue

```bash
npm run build:all-in-accounting
npm run verify:accounting
npm run test:dev-tools
npm run probe:impact-tree
```

This acceptance covers fresh application and identical reapplication of the new
profile. A populated old-API migration and adaptation of the separate MetaSol
frontend remain separate tasks. Reporting values use each event's dated rate;
current-rate valuation of remaining balances requires an explicit calculation.
