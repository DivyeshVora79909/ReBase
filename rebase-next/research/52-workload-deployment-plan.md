# G8 workload and deployment assurance

**Prepared 2026-10-25; implementation is now explicitly assigned.**
[Current checkpoint results](53-workload-deployment-result.md) track execution;
the preparation review below remains historical. The user
selected preparation so another agent can implement this bounded goal. G7.0–G7.6
remain [accepted](51-storage-conformance-result.md). This plan supplies the next
implementation checkpoints; preparing it does not select or execute them.
The [preparation review](evidence/2026-10-25-g8-preparation.json) records baseline
fingerprint checks and the limited documentation verification performed here.

## Goal and boundaries

Give developers repeatable evidence that the assembled backend behaves correctly
under sustained churn, resource pressure, excess demand and specified deployment
failures, and that its release artifact works outside the checkout. Reuse
ordinary functions, explicit inputs and the existing model/API. Each profile
owns a distinct new claim; calculations and checks are reused.

The implementation goal is **G8.0–G8.5 below**. Default churn measurement is
300 seconds per selected backend. Longer runs are explicit profile choices.
Five minutes establishes a five-minute observation, not absence of all leaks
or unrestricted production readiness. A developer can compose workloads,
observations and checks without running every profile.

No new health endpoint, monitoring service, dashboard, universal fixture engine,
configuration language, plugin registry or query language is required. Existing
`/health` remains liveness-only. Production observation can reuse read-only
samplers; mutation and fault profiles own isolated stores/namespaces and
processes. Fix shared core code only for a reproduced failure, with its focused
regression. Do not introduce a second mutation, calculation or recovery engine.

G6 accounting, TiKV, frontend, live providers, migrations and general million-
record capacity remain deferred. Native commit-ack interception, replicated
failover and disk/power-loss tests require controlled infrastructure; classify
unexecuted cases explicitly. HTTP response loss is not their substitute. No new
cloud infrastructure is presumed.

## Baseline and reuse

Source 0.16.0 uses store 10 /native codec 7 /effect codec 4 /API 4. Read
[G7.5](50-scoped-coordination-result.md), [G7.6](51-storage-conformance-result.md)
and [backend operation](../docs/storage-backends.md) before changing shared paths.

| Obligation | Existing evidence or implementation | New G8 obligation |
| --- | --- | --- |
| Atomicity, tree/index/authority correctness, scoped coordination, replay | G7.5/G7.6, source oracles and complete thirteen-table observations | Apply independent checks to sustained workload outcomes |
| HTTP response loss and application SIGKILL/reopen | `tools/g7_http.py`, original-ID receipts, restore/archive checks | Distinct database-service outage/reconnect conditions |
| Admission after response timeout | `server::tests::deadline_keeps_admission_until_the_real_transaction_finishes` | Controlled overload plus bounded producers and recovery |
| Fixtures/workloads | `harness.py`, `capacity.py`, `verify_cases.py`, `verify_oracles.py`, `verify_explore.py` under `tools/` | Duration-controlled CRUD and shared bounded observations; existing capacity churn is a retained-role exhaustion experiment |
| Packaging | `tools/package.py`, deployment templates, historical 0.6 acceptance | Current feature/backend/model inventory and extracted-release workflows |

Verify fingerprints before reusing evidence. Re-run only obligations affected
by changed source, formats or a new failure. Do not invoke every G7 suite,
`verify --mode check` or historical population sweeps as a default G8 substep.
G7 establishes more than internal integrity; G8 adds operating-condition evidence.

## Composition contract

Keep the entry point a thin script, reusing ordinary functions. The following
responsibilities are a suggested shape, not a new wire API or mandatory wrappers:

- **Prepare:** explicit target and trusted scenario recipe produce a valid
  fixture and independent expected facts. Record model identity, seed and recipe.
  Construct required indexes/dependencies and validate before timing.
- **Run:** a workload iterator emits ordinary operations under explicit duration,
  rate, concurrency and pending-work budgets. Observers and controlled fault
  context managers are ordinary arguments. Return results/artifact paths.
- **Check:** independent expectations consume observations/outcomes and check
  arithmetic, structure, receipts and declared resource budgets. Checks also work
  without the convenience runner.

Use small plain Python values/functions, existing Rust controls and standard
libraries initially. Ordinary argument validation suffices; no second JSON
Schema or executable configuration DSL is needed. Add a dependency for a
concrete gap only. Artifacts describe trusted functions/parameters; never eval
or dynamically import arbitrary code from a report. Preserve original-target
receipt replay versus new-target logical replay.

A profile identifies backend/cluster/namespace or directory, compiled model,
scenario, seed, live population/identity pool, action weights, clients, offered
rate, maximum pending work, duration, warm-up, sampling, cleanup and resource
budgets. Defaults must fit the binding. Unknown fields, impossible shapes and
unbounded queues reject during preflight.

Use non-accounting scenarios: equipment for ordered trees/time/private-output
churn and Quantity for direct cascade/fanout checks. Reuse an existing scenario
when it covers the obligation. A small benchmark binding needs a demonstrated
missing case first. JSON types alone cannot generate valid global trajectories:
use known scenario transitions and independent facts, with tagged deliberate
invalid cases. Record requested versus achieved coverage and work.

The default duration profile uses equipment, one sequential writer and at most
two bounded readers, a 64-ID pool including fixture roots, 30-second warm-up,
300-second measurement, one-second sampling and 30-second cooldown. Start with
at most eight pending client operations, two new mutation submissions per second
and a hard 800-new-operation measurement
budget; preflight must also account for fixture/warm-up receipts and reserve
space before 1,024. Replays and reads do not allocate slots. For a longer
continuous epoch, explicitly choose a feasible write rate/receipt budget or
shorter PID epochs; do not silently stop CRUD while the clock keeps running.
Quantity is a targeted cascade/overload profile, not another mandatory full
duration matrix. These are conservative defaults, not measured capacity.

### Scale and capacity

`n` is entries in the relevant tree, `m` is actual memberships maintained per
record, and `r` is the edit's actual invalidated/evaluated closure. Report actual
shape/counters; total database population is not tree depth. A profile number
cannot add memberships absent from its compiled model.

Current bounds include 4,096 public sources, 8,192 outputs, 16,384 retained role
reservations, 1,024 receipts, 64 commands per mutation, 200,000 mutation work
units, bounded inventories and 64 MiB backups. Population counters are `u16`;
bindings can be smaller. FoundationDB also has transaction size/lifetime limits.
Preserve these bounds and test rejection. Raising constants or bypassing index
maintenance is not million-record acceptance. Count/format/envelope/streamed-
checking expansion needs a separately named goal. Label a large-tree
microbenchmark separately from application capacity. Structural capacity
fixtures do not establish executed request counts.

## Observations, pass criteria and artifacts

Use shared bounded samplers, not another telemetry service. Record:

- Offered/submitted/completed/unresolved work, successes, reads, replay and
  rejection counts by HTTP status and RPC kind; latency distributions and
  throughput. Separate setup, validation and maintenance time.
- Available engine work: loads/bytes, visits, rotations, changed keys and causal
  candidates/evaluations. Missing counters remain unsupported, not zero.
- Owned-PID RSS/high-water memory, CPU, descriptors and threads; logical
  populations/roles/slots; physical backend bytes at fixed cadence. Separate
  application, controller and database. FoundationDB namespace labels are not
  data paths: observe its owned server/data/logs explicitly.
- Warm-up/steady/tail/cooldown markers, PID lifetimes, model/backend/format,
  seed, host limits, source/binary identities, sample gaps and observer overhead.

Declare budgets before measurement. G8.0 chooses documented defaults from the
available host and a short baseline; overrides remain explicit. Compare peak,
tail and growth in comparable windows with equal live inventory. Physical files
or RSS need not shrink immediately: WAL, caches, allocator high-water and
retained identities can be intentional. Attribute growth before calling it a
leak. Include receipt/epoch/reservation retention in that accounting. Use a
read-only cooldown with constant inventories for plateau comparisons; if
comparable windows are unavailable, report no leak-trend verdict while retaining
the absolute-budget results. Budgetless measurements do not certify resource bounds. Changing thresholds
after failure needs a new explained run. A test-only injected trend/checker
control must demonstrate excessive-growth rejection; it is not a product leak.

Keep counters/samples bounded in RAM. Stream private traces, plans and samples
under explicit byte budgets; do not attribute controller growth to the server.
Replay needs a declared complete trace or logical checkpoint plus retained
suffix. Required evidence truncation or budget exhaustion is incomplete, never
silent success. Public summaries omit credentials, complete backups and sensitive
bodies. Retain JSON/JSONL/CSV plus a concise readable report; no custom UI.

Pass requires expected outcomes, achieved coverage, resolved operations and all
required observations/budgets. Report `passed`, `failed`, `incomplete` or
`unsupported` per obligation and aggregate honestly; a mandatory unsupported
case narrows the accepted matrix or blocks its acceptance. Use existing exit
conventions where practical: 0 pass, 1 failure, 2 incomplete.
Seeded actions are reproducible; concurrent winners, UUID tokens and OS schedules
need not match byte for byte. Save actions, outcomes and barriers. Compare token
relationships and independent arithmetic, not a global revision sequence.

## Implementation checkpoints

Each checkpoint needs a coherent commit on existing `main`, evidence and updated
continuation. Local commits suffice; normal pushes can be used when credentials
are available. Stop on a failed required check, diagnose/fix it and repeat only
affected runs. Preparation below is not executable acceptance.

### G8.0 — inputs, observations and preflight

**Deliver:** thin workload/observer/check composition, backend/source preflight,
explicit defaults, resource/evidence budgets and bounded artifacts. Reuse
`Backend`, client calls, `backup_image`, `check_archive`, pure scenario oracles
and replay/minimization helpers. Inspect actual arguments and observation
ownership; do not build parallel implementations.

**Accept:** a tiny scenario works through explicit function composition and CLI
with equivalent checks. Invalid configuration, missing SDK/backend, incomplete
data and injected bad observations fail clearly. Resource-checker negative
controls reject the intended class. No server API/core change is needed. Record
the exact default profiles and host budgets for subsequent stages.

### G8.1 — sustained churn and resource behavior

**Deliver:** seeded valid CRUD plus deliberate invalid operations, no-op, stale
edit and replay, using bounded live records and independent expected facts.
Default measured duration is 300 seconds per selected backend after warm-up.
Short development runs are labeled shorter smoke profiles. Coverage floors
force every action class to execute, not just receive a nonzero random weight.
For the default continuous epoch require at least 100 successful creates, 100
updates, 100 deletes, 500 reads, ten replays, ten no-ops, ten expected invalid
attempts and ten stale edits; planned actions can guarantee these floors before
seeded mixing. A shortened/custom profile declares its own floors in advance.
Long runs renew authentication explicitly without altering saved operation
identities/contexts.

**Receipt/process constraint:** embedded-store archive is offline and receipts
cap at 1,024. Do not add an admin HTTP API just for this test. Separate an
uninterrupted memory epoch from lifecycle epochs. Include a paced 300-second
memory epoch in one application PID, with enough free receipt slots, a finite
identity pool and substantial CRUD progress. Archive/restart outside that
window. Other PID epochs are reported separately; restarts do not establish
continuous-process leak freedom.

Then execute at least two real receipt allocation/archive cycles: full capacity
reached by executed requests, replay at full capacity, new-request unchanged-state
rejection, archive preservation/expiry and resumed CRUD. Reuse the existing
complete-image/receipt observers. Resolve every in-flight/unknown operation
before archive; new intents can obtain the new context afterwards. Reuse bounded
IDs/roles or report expected reservation accumulation and its capacity. Never
silently reset a store to conceal exhaustion.

**Accept:** achieved action/cycle coverage, source-derived/literal values,
complete thirteen-table integrity, receipt outcomes, original-ID replay and
predeclared resource budgets pass. Rejection image comparisons require quiescence;
another successful writer is not partial publication. Keep the measured PID
continuous; stop/reopen for complete offline observations outside that window.
Check controller/observer retention too. A five-minute run makes no longer claim.

### G8.2 — overload, pressure and admission recovery

**Deliver:** bounded read/write producers and queues, fixed client/rate steps,
hot versus independent roots and an expensive bounded cascade. Distinguish
offered, admitted and completed work and limit rejections. Bound executor
submissions as well as thread counts; never enqueue the entire run in advance.
Use targeted geometric population/fanout levels within current model bounds and
a few combined demanding cases, with achieved `n/m/r` and rejection boundaries.
Avoid a full Cartesian sweep or multiplying small-case timings into a fictitious
large-state result. Reuse a matching prepared fixture where its identity permits.

Reuse the existing real-writer deadline test for permit retention; narrowly
extend it for uncovered/changed obligations. Use deterministic barriers for
saturation/timeout correctness and finite actual HTTP load for measurement.
Slow storage/requests need an identified controllable boundary, not a production
delay endpoint or correctness inferred from sleeps. Include bounded slow-input/
connection pressure if claiming ingress resource protection, not just worker
admission.

**Accept:** admitted native work stays within configured permits, overload
rejects visibly, timed-out work retains its permit until completion, and release/
drain restores service with correct original receipts. No hidden mutation retry
or duplicate occurs. Queue/memory/FD/thread/latency budgets meet the declared
finite load. Integrity/source checks pass after drain. Arbitrary unbounded
connection pressure is not certified.

### G8.3 — database outage and precise recovery boundaries

**Deliver:** stop/restart an owned disposable FoundationDB service while the
application remains alive; record requests before/during/after interruption.
Prove reconnection using ordinary authenticated DB operations; a socket or
`/health` alone is insufficient. Bound deadlines, verify PID/cluster/namespace
ownership and release/clean up on every exit path. For embedded adapters reuse
applicable process/restore evidence; nonapplicable network cases are not passes.

Existing HTTP loss proxies are reusable evidence, not native commit-ack proof.
Any added disconnect/delay must establish the exact connection and phase it
reached. A coordinator-only proxy can miss FoundationDB's advertised endpoints.
Keep native commit-ack isolation unverified if controlled infrastructure is
unavailable; never manufacture a conflict/definite abort to stand in for it.
Replicated failover and disk/power-loss infrastructure are not implicit additions.

**Accept:** the same application serves DB operations after recovery within its
recorded budget, with correct final state. Preserve success/confirmed abort/
limit/unknown classifications. Reconcile original IDs and contexts without
replacement mutation submissions. Absence while a worker may run is not rollback;
establish completion/quiescence or mark unresolved/incomplete. Compare all
application tables after drain, check atomic outcomes and no duplicate
application, and name actual outage/recovery times and remaining fault gaps.

### G8.4 — current release artifact and configuration

**Deliver:** extend the existing packager only as required to record explicit
Cargo features, supported backends, six current model identities/formats, native
prerequisites and compatible deployment templates. It currently builds default
features and inventories three models. Build committed sources outside Git with
one shared cache. Default acceptance needs a redb artifact without the FDB SDK
and one feature-enabled artifact covering selected adapters. A SurrealKV-only
artifact is required only if advertised as a supported variant.

Run extracted tools/fixtures/configuration against the packaged executable
outside the original checkout, with explicit native-library paths. Verify
checksums/catalogs, backend initialization, authenticated workflows, recovery/
restore and clear configuration failures. Reuse existing scenarios with current
tokens. No original checkout paths or ambient tool imports may supply missing
bundle contents. Use the packaged binary for bounded profile smoke checks;
reuse matching G8 load evidence only when source/features/binary fingerprints
justify it. This is not another full stress campaign.

**Accept:** artifact identities, prerequisites and valid/invalid configuration
results are recorded. Missing-library/backend/model/destination controls are
clear; extracted representative non-accounting workflows pass on each advertised
backend. Generated private data/secrets are excluded. No implicit migration,
remote deployment or production DB modification occurs. Keep historical 0.6
release acceptance distinct until a current bundle passes.

### G8.5 — evidence and developer handoff

**Deliver:** one documented entry point and ordinary importable functions,
composition examples, structured results and readable summaries with exact
supported duration/load/backend/artifact limits. Each obligation names reused
or newly executed evidence/status. Do not repeatedly add reused case counts or
call an unexecuted long soak successful.

**Accept:** default 300-second churn/resource evidence and overload/recovery
profiles exist for all three advertised adapters, or the supported release matrix
is explicitly narrower. The extracted release passes that matrix. Every outcome
is resolved or incomplete, no mandatory case is silently skipped, and owned
workers/servers/queues drain or stop on success and failure. Report failed trials,
fixes and gaps honestly. Longer soak/failover are named extensions, not inferred
from five minutes. Publish a result and update the continuation/stop boundary.

## Delegation and continuation

After explicit implementation authorization, assign bounded file ownership:
scenario/churn and source expectations; bounded samplers/report checks; new
fault controls; later packaging. The coordinator owns shared helpers, CLI wiring,
resource defaults, build identity and commits. Agree contracts first. Independent
observer/generator work can run in parallel after G8.0; integration acceptance
follows checkpoint order. Do not give multiple agents one file or run competing
load measurements on the same host/cluster.

Use one Cargo owner, two jobs, incremental off and matching caches. Run short
controls before 300-second profiles and repeat only affected checks after source
changes. No compatibility adapter or second compiler/runtime is needed.

Suggested goal for a fresh implementing agent:

> Read AGENTS.md, CONTEXT.md and research/52-workload-deployment-plan.md. Implement
> G8.0–G8.5 on existing main, preserving accepted G7 contracts/evidence. Reuse
> ordinary functions and independent checks. Default churn measurement is 300
> seconds, with continuous-PID memory evidence and separate receipt/archive
> epochs. Bound producers, observations and artifacts. Verify actual overload,
> owned database outage/recovery and the extracted current release. Use one Cargo
> owner and small delegated tasks; commit verified checkpoints and keep context
> current. Diagnose unresolved required failures instead of marking them passed.
> Keep G6, TiKV, frontend, million-record expansion and unprovided replicated/
> power-loss infrastructure deferred. Complete only the stated matrix and report
> every unsupported or incomplete obligation.
