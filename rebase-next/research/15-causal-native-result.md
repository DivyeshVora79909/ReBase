# Native causal settlement result

**P1 accepted, 2026-10-22.** This closes the native M3/M5 settlement gate for the
bounded model in [paper 13](13-local-prototype-plan.md). P2–P4 remain active;
the autonomous local-prototype goal is not complete.

The same point workspace and intrusive trees now settle authored entries,
strict-prefix adjustments and private outputs, including the reporting diamond.
Discovery follows old/new routes, while final output/query intersections alone
define ordering. All affected old outputs are detached before evaluation.
Zero feedback still rejects; equal totals do not erase causal dependencies.
Validation queries remain separate from calculation edges.

Private role UUIDs are allocated and collision checked transactionally. Inactive
bindings survive reenabling; deleted producers retain retired reservations.
Ordinary commands cannot address private contracts or reuse reserved identities.
Final reference checks handle managed-output removal and parent-first deletion.

| Corpus | Cases | Operations | Commits | Rejections | Equal reopens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Causal extension | 39 | 55 | 38 | 17 | 39 |
| Original connected regression | 68 | 93 | 53 | 40 | 68 |

The independent Python checker compares complete real redb snapshots to source
and allocation-history expectations. It scans every actual tree independently
and verifies records, queries, routes, roots, private outputs and reservations.
All 148 retained old snapshots stayed unchanged. All 57 rejected attempts left
the complete application byte map unchanged; partial/full physical abort hooks
are included. Every case reopened to identical bytes.

The checker has 32 invalid-state controls and two incomplete-scope/budget
controls, including 12 new private inventory/identity/query controls. A focused
Rust test compares strict prefix traversal against authored scans with equal
times, negative values, removals and both i64 extremes. Explicit native work
assertions cover disconnected components, reporting-only changes, shared sources
and allocation retries. The integrated 14 Rust tests, formatting and Clippy with
warnings denied pass. [Evidence](evidence/2026-10-22-local-prototype-p1.json)
records fingerprints, counts and raw observation paths.

The codec is now `native-slice-kv-2`. Empty Account subscriber headers increase
the original baseline from 33 to 35 rows; the causal baseline has 76 rows.
Earlier dated evidence retains its original codec/counts. Conservative root
invalidation, fixed actor/tenant, input/population/reservation limits and authored
query shapes remain explicit bounds. This establishes neither arbitrary model
loading nor production/distributed capacity.

Continue with the [local interface contract](14-local-interface-contract.md).
No original ReBase/MetaSol code or database was changed.
