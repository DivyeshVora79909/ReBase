# N4 — Node experiments and workload result

Status: **accepted within bounded scope** by root on 2026-10-26 after final
independent review and the N0–N4 suite. The retained run passed 95 tests, with
0 failures and 0 skipped tests, in 3691.320752 ms. Exact output is retained in
[N4 evidence](evidence/2026-10-26-n4-node-experiments.json) and its full-suite
[log](evidence/2026-10-26-n4-node-final.txt).

N4 adds ordinary Node ESM functions for bounded workloads, observation,
experiments, and independent checking. `runWorkload` accepts caller-owned async
scenarios and state, bounds offers, concurrency, duration, samples, and retained
artifact bytes, and returns bounded raw observations plus measured cost fields.
`checkRun` checks those observations against a separately supplied source-only
oracle and reports passed, failed, and incomplete obligations. `walk`, seeded
`explore`, bounded failure shrinking, and logical replay are separate from
resending an exact saved original plan and reconciling an unknown result by
status.

The real Equipment and Quantity receipt-progress trials reuse the existing
N2/N3 client and population functions. Equipment covers create/update/delete,
including a deliberately dropped committed response, restart of the owned
local service, and status reconciliation against the same operation ID without
resubmission. Quantity checks exact committed receipt progress. Both retain
bounded observations and source facts. The bounded source checker independently
checks record identity, authored inputs, derived values, root/query/role
inventories and contents, and source-derived summaries where their ordering is
known. It marks Measurement query-result and selected-identity payloads
incomplete. Equal-time mixed-sign Equipment prefix extrema are also incomplete
because inspect does not expose the hidden leaf ordering needed to derive them.

Physical tree verification remains incomplete: native inspect lacks tree nodes,
child links, heights, leaf order, and per-node aggregates. Native `store.check`
is an engine integrity check, not an independent source oracle. N5 owes a
typed-backup structural checker, followed by N6's physical-snapshot path. The
older Python source-only checks do not independently verify physical tree
links; retain their workflows until the N6 semantic replacement/deletion ledger
is complete, without treating them as physical-structure evidence.

The retained test output records both trial durations, native/model identities,
observations, cost fields, receipt IDs and the Equipment lost-reply recovery
steps. These are bounded local trials; they do not establish general capacity,
distributed latency, exactly-once effects, database/disk/power-loss recovery,
replicated failover, or arbitrary callback containment. Callbacks that ignore
cancellation can remain unresolved; such work must leave a report incomplete.

See [N4 contract](68-node-experiment-contract.md) for frozen semantics and
[evidence](evidence/2026-10-26-n4-node-experiments.json) for exact command,
runtime identity, review, cleanup, and bounded claims. N5 is next; N6 and S0–S3
and F0 remain pending.
