# G8 workload and deployment results

G8 implementation is explicitly assigned on 2026-10-25, on existing `main`.
Verified checkpoints are committed locally; the user requested no pushes.
[Paper 52](52-workload-deployment-plan.md) owns the scope and fault boundaries.
G7.0–G7.6 remain accepted and are reused where fingerprints and obligations match.

## G8.0 — bounded composition and preflight

The implementation provides ordinary prepare/run/check functions, one thin CLI,
finite seeded equipment trajectories, a source-only oracle, bounded private
streams, separate process/file observations, receipt-room preflight and explicit
resource checks. No core, wire, storage format or server endpoint changes.
The client only adds the observed HTTP status to its existing error objects;
it still makes one request, preserves saved contexts and never retries.

The [G8.0 evidence](evidence/2026-10-25-g80-workload-inputs.json) records short
real HTTP profiles and CLI/function composition equivalence. The accepted
executable remains G7.5's optimized feature-enabled binary, SHA-256
`288232e18700d24ef63c7db785f3aff51426a4c6e35b579a949f846d5a36b632`.
All accepted core/Cargo fingerprints match. Changed client/tool fingerprints are
identified separately; unchanged G7 native campaigns are not repeated.

Twenty-one focused Python controls cover feasible/unknown/unbounded inputs, missing
backend/SDK, missing/truncated observations, original PID continuity and resource
budget violations, including an injected excessive-growth checker control. Six
existing client controls pass with the added HTTP-status observation. An actual
missing-native-library preflight returns a clear failure. This is a negative
control, not an unsupported successful run.

Two initial failed smoke trials remain retained: an invalid interval produced
`invalid_input`, so the deliberate invariant witness now uses valid simultaneous
reservations whose complete-time balance becomes negative; the complete integrity
count includes native private outputs, so its expectation now checks public
sources plus active outputs. Neither correction changes product behavior.

[The guide](../docs/workloads.md) records the exact default profiles and budgets.
The short baseline selects budgets before any G8.1 measurement. It is labeled
short smoke evidence and establishes no 300-second acceptance yet. Continuous
memory epochs and offline receipt/archive lifecycles remain separate.

## G8.1 — sustained churn and executed receipt lifecycles

All three adapters pass a paced 300-second measurement in one application PID,
between 30-second warmup and read-only cooldown windows. Each measured run
executes 181 successful creates, 181 updates, 180 deletes, 600 root reads,
13 original-ID replays, 14 no-ops, 14 expected invariant rejections and 17 stale
edits. Authentication renews once without changing saved operation contexts.
The [G8.1 evidence](evidence/2026-10-25-g81-churn-resources.json) fingerprints
the original private results and separate independent checks.

The independent checker reconstructs source arithmetic and checks 608 transient
publications per adapter, with no missing snapshots. It checks raw action counts,
PID/duration samples, all thirteen-table observations, original receipts, operator
events and complete artifact budgets. Its nineteen negative/positive controls,
ten workload/publication controls and fourteen sampler controls pass. Current
checker/tool fingerprints remain distinct from recorded run-start fingerprints.
No Cargo build or earlier G7 campaign was repeated; all 72 core/Cargo hashes match.

| Adapter | Peak application RSS | Peak controller RSS | Peak separate database RSS | Full receipt cycles |
| --- | ---: | ---: | ---: | ---: |
| redb | 35.0 MiB | 27.1 MiB | Nonapplicable | 2 |
| SurrealKV | 40.1 MiB | 27.6 MiB | Nonapplicable | 2 |
| FoundationDB | 43.6 MiB | 27.1 MiB | 89.7 MiB | 2 |

All predeclared RSS/high-water, FD, thread, physical-growth, sample-gap, observer
and artifact budgets pass. Constant-inventory cooldown growth is zero for redb
and SurrealKV; FoundationDB application growth is 3.6 KiB, with zero controller/
database growth. This establishes only the recorded five-minute observation and
short cooldown comparison. Action latency includes preparation and source checks;
supporting HTTP calls are not separately advertised as transport throughput.

Each store then reaches 1,024 receipts through real requests twice: 415 new fill
requests from 609 existing receipts, then 1,021 from three post-archive receipts.
At full capacity, original replay succeeds and a new intent rejects with complete
thirteen-table unchanged-state evidence. Offline archive preserves every required
table, expires the old context, and resumes all CRUD classes. Every submitted
original is resolved before archive, no reset is used, and operator logs account
for 2,052 committed events per store across the complete campaign. These lifecycle
PID epochs remain separate from the uninterrupted memory measurement.

One initial redb trajectory correctly rejected reuse of a retired Reservation
producer UUID. Its original intent was resolved as absent after drain and the
failed store remains retained. The corrected trajectory reuses Delivery IDs for
public CRUD and toggles existing Reservations for private-output churn, retaining
four stable role identities. No storage behavior changed. Final publication now
counts its own report and the complete archive suffix; exact-byte and exhaustion
controls plus a short redb CLI/raw-check run verify that reporting correction.
Original long-run artifacts are preserved, with final totals recomputed separately.

## G8.2 — finite overload and authored geometry

Fresh real HTTP runs and independent raw-artifact checks pass on redb,
SurrealKV and FoundationDB. Each offers/submits/completes 600 finite operations
across paced rate/client steps, hot and independent business roots and two
bounded bursts. The runs expose 16 /17 /48 busy rejections, respectively;
315 original intents per store are resolved with no replacement retries.
The [pressure evidence](evidence/2026-10-25-g82-pressure.json) records exact
counts, run identities, resources, actual geometry and rejected-state checks.

Equipment uses 4/16/64 added reservations and actual evaluated closures of
4/10/34, with root populations up to 69 entries. Quantity independently tests
1/4/15 dependents and a complete unchanged-state capacity rejection; it declares
no tree memberships. These are actual bounded shapes, not million-node claims.
Queue/worker/drain, resource, source arithmetic and thirteen-table checks pass.
The accepted G7.5 real-writer deadline/permit case is reused with matching core
fingerprints. Voluntarily closed slow-input sockets establish only finite
connection pressure, not an unlimited-ingress or body-read-timeout guarantee.

`bounded_step(requests, submit, hooks...)` supplies the ordinary composition
seam; scenario oracles remain explicit functions. Raw stage markers now permit
independent elapsed/rate/drain reconstruction. The initial redb run is retained
as incomplete: the receipt reconciler originally treated a stage-end marker as
an operation. A focused trace/reconciler control covers the correction. CLI
pressure checking now selects the complete evidence root, and nonpassed profiles
return nonzero status. Paced throughput remains achieved load, not maximum capacity.

## G8.3 — owned FoundationDB service interruption

The [outage evidence](evidence/2026-10-25-g83-outage.json) records a real owned
service stop/restart while the application PID stays alive. Authenticated DB
requests fail during downtime; a DB read succeeds after 8.232 seconds. Two
original mutation IDs reconcile as not observed, with no replacements. Complete
before/after thirteen-table images match, native integrity passes, and source,
resource, service-identity and offline raw-artifact checks pass.

One superseded trial exposed a two-byte report drift when the server config
was restored after publication. Restoration now precedes publication, the outer
cleanup remains exception-safe, and the offline checker compares final actual
and reported artifact bytes. Thirteen fault controls cover missing, contradictory
and altered evidence. This is local service-outage acceptance; native commit-ack,
replicated failover and disk/power loss remain outside the executed boundary.

## Incoming-work review and continuation

The [continuation review](evidence/2026-10-25-g8-continuation-review.json)
records the replacement of unverified tip 1fe6310, isolated G8.1 baseline controls
and a current 0.16.0 build. All 72 core/Cargo and 13 model hashes match. Historical
G8.1 raw directories were in another environment and are unavailable here; its
committed evidence is retained rather than represented as a newly rerun campaign.

G8.0–G8.3 are accepted within those boundaries. G8.4 release tooling has focused
Python controls but still requires current committed-source packages and real
extracted acceptance, followed by G8.5 evidence/handoff. G9 population tooling is
prepared in [paper 54](54-composable-developer-tools-plan.md), with no runtime
implementation selected by this G8 continuation.

### Historical continuation after G8.1

G8.0 and G8.1 are verified. Next is G8.2: finite overload, bounded ingress and
targeted equipment/Quantity geometry, followed by G8.3–G8.5 in checkpoint order.
One coordinator owns Cargo (two jobs, incremental off, matching shared cache).
Delegated files have explicit ownership; load measurements use one host/cluster
at a time. G6, TiKV, frontend, million-record expansion and unprovided native
commit-ack, replicated and power-loss fault infrastructure remain deferred.
