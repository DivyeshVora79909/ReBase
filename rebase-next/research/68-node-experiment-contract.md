# N4 — Node experiment and workload contract

Prepared 2026-10-25. This freezes the small developer interface for N4 before
its implementation. The public module is `tools/node/workload.mjs` and exports
exactly two runner functions: `runWorkload` and `checkRun`. Scenarios and source
oracles are ordinary functions supplied by callers or examples; they are not
registered plugins and do not form a second workflow language.

The adjacent `experiments.mjs` module keeps only reusable algorithms that own
historical verification work: `walk`, seeded `explore`, bounded `shrinkFailure`,
and `logicalReplay`. Source-only expectations are separate ordinary functions
in `oracles.mjs`. Exact original-plan resend and unknown status reconciliation
are shown as a composition in `examples/n4-original-intent-replay.mjs`; the
runner does not wrap every client operation in another SDK method.

## Workload composition

`runWorkload({ scenario, state, profile, signal, observe })` consumes a caller
scenario as an async iterable of action objects. Each action has a stable local
ID, a descriptive kind, and a `run({ state, signal })` function. The runner
limits offers, concurrency, elapsed time, sample count and retained artifact
bytes. It invokes one `next()` at a time and never builds an unbounded pending
queue. `state` is caller-owned and explicit. The runner owns only its report,
timers and outstanding callback references.

The runner retains bounded raw observations, including each action's request
description when supplied, returned value or error class, timing, and terminal
state. It returns the raw observations and a producer summary for convenience;
the summary is not evidence that the workload passed. Cancellation aborts the
signal and stops requesting actions. JavaScript cannot forcibly stop an
arbitrary callback or async iterator: unresolved `next()`, `return()`, sampler,
and action work is recorded and keeps the report incomplete. If a completed
result exceeds the artifact bound, its action status and original request stay
retained while the result is marked truncated and the report remains incomplete.
Late completions are discarded from the returned report. Callbacks must use the
supplied signal and avoid mutating retained report objects.

The profile has required finite positive `durationMs`, `ratePerSecond`,
`maxActions`, `concurrency`, `maxPending`, `maxObservations`,
`maxArtifactBytes`, and `sampleIntervalMs` bounds. `maxPending` cannot exceed concurrency and the native
hard limits remain authoritative. An optional `observe` function samples
explicit process handles or PIDs; unsupported platform metrics are marked
unavailable. A caller observation callback is trusted and may have arbitrary
cost, which the report measures as callback time rather than calling O(1).

## Independent checking and experiment distinctions

`checkRun({ run, oracle, maxChecks })` checks the retained raw observations and
source facts using a separately supplied source-only oracle. It does not trust
producer pass flags, cached totals or production settlement. The checker returns
named passed, failed and incomplete obligations; missing or truncated
observations cannot pass. Source-only expected-value functions remain separate
ordinary exports in example/oracle modules so multiple scenarios can share the
runner without coupling their business expectations.

The bounded Equipment, Quantity and Measurement source checker verifies authored
record identities, exact authored contract/input facts, independently computed
derived values, Equipment private output record facts, root/query/role address
inventories, query source/operation/phase/channel/range, role retirement/output
links, and typed source-derived root summaries. Equal-time leaves count as
separate root members while boundaries remain between distinct timestamps.
Measurement query-result and selected-identity payloads remain incomplete
because they are not yet interpreted independently. Equal-time mixed-sign
Equipment prefix extrema remain incomplete because inspect does not expose the
leaf order needed to derive their chronological extrema. These logical
obligations are distinct from physical tree verification: inspect does not
expose tree nodes, child links, heights, leaf order or per-node aggregates, so
those remain incomplete and are carried to N5's typed-backup checker and N6's
physical-snapshot path. Native `store.check` remains an engine integrity check
and is not counted as an independent source oracle. Older Python source-only
checks do not independently verify physical tree links and do not satisfy this
obligation; their workflows remain until the N6 semantic replacement/deletion
ledger is complete.

Walk explains an already recorded trace. Check validates its raw observations.
Explore creates seeded logical actions against a disposable target and may
shrink a failure within a fixed attempt/time budget. Logical replay rebuilds
equivalent actions with remapped IDs. Original-intent replay resends the exact
saved plan, operation ID and context. These operations remain distinct so a
rebuilt logical case can never be mistaken for a retry of an unknown original
write. Unknown outcomes preserve their original plans and are reconciled only
through the existing client status operation; they are never inferred to have
rolled back or automatically retried. Only a confirmed committed receipt
resolves original-intent replay; `not_observed`, malformed, and future status
values remain incomplete.

## Costs and claims

Reports include separate generation, setup, RPC, queue, native, and checker
cost fields. The runner measures time spent advancing the scenario as generation
time, waiting in its bounded scheduler as queue time, and action callback time
as callback/RPC time. Setup can be supplied only as a measured setup duration.
Native execution cost is `null` unless a supported native observation exposes
it; it is never fabricated as zero. Resource samples identify PID and native
metadata explicitly. Offered/completed counts, exhaustion, cancellation,
unresolved callbacks, artifact truncation, backend/model identity, limits, seed
and exact duration bound every claim. A paced local run does not establish
general capacity, multi-host latency, exactly-once effects or arbitrary
callback containment.

## Reused capabilities and obligations

N4 reuses N3 population for setup and the existing N2 client/operator/service
ownership. Ordinary scenarios cover equipment mutation/read/replay/failure,
Quantity arithmetic and observation selection independently. Workload profiles
cover scoped churn and receipt cycles, overload/backpressure, service/database
outage with lost replies and recovery, and resource/host observations. Keep
complete source inventory, structural inventory and summary checks derived from
source facts; production settlement is not an oracle. Failure shrinking is
bounded and retains the original failing trace. Corrupt report controls must be
rejected. Real Equipment and Quantity receipt-progress trials record their
actual duration and identities; the Equipment trial drops a committed reply,
restarts the owned local service and reconciles the same operation ID by status
without resubmission. They do not expand capacity claims or prove database/disk/
power loss, replicated failover or multi-host latency.
