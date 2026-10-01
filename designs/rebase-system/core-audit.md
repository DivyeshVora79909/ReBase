# Core audit — baseline 2026-09-26; K1–K3 update 2026-09-28; K4b/K5 update 2026-09-29

## Lead recheck — 2026-09-29

The [focused recheck evidence](./evidence/2026-09-29-lead-checkpoint-audit.json)
records fresh compiler checks for all three profiles, accounting native
validation, credential/authentication/environment checks, and the runtime
probe (53.23s). The expanded H8 probe (53.34s) observed a real conflict between
two independent sessions, verified rollback and retry with the same business
identity, and reapplied the schema with populated runs and used outputs.
Source/recipe oracles and the post-reapplication output-date guard passed.

No engine or domain-schema fix was needed. The audit corrected stale root
README/readiness status, narrowed the blanket completion wording, and closed
the two H8 verification omissions. H8 physical cost measurement, H4b5c policy,
and H0 compression remain open. The original K4b/K5 whole-worktree fingerprint
and H8 evidence remain historical; this recheck adds 125 per-file fingerprints.
The full verify suite and positions probe were not rerun in this focused audit.

## Current conclusion — 2026-09-29

K1–K5 passed on the recorded dirty working tree. K4b verified root-hidden
platform credentials, owner/delegate write-only BYOC secrets, fixed trusted
platform binding, current permission checks before privileged credential load,
and the authentication/runtime paths. K5's full `npm run verify` and the
changed positions probe passed. Exact commands, source fingerprint, timings,
and limits are in the
[2026-09-29 evidence](./evidence/2026-09-29-k4b-credentials.json).

This supports core reliability for that tested snapshot, not production
certification. Live provider delivery, Redis Cluster, production migration,
representative capacity limits, and a populated production rollout of the
revised all-in-accounting profile remain open. H1/H2/H3a/H3b passed for the revised target profile; H3c's bounded
fixture, H4a, H4b1, H4b2, H4b3, H4b4a payer-side supplier withholding, and
H4b4b customer-withheld TDS and H4b5a paired claim offset passed their scoped
gates. H4b5b treasury-backed remittance passed; see [H4b5b evidence](./evidence/2026-09-29-h4b5b-tax-remittance.json).
H4b5c residual policy remains future and unresolved. H5a's complete-timestamp
stock floor, H5b physical return with dated source capacity, and H5c standalone
receivable cash refund passed. H6a ordered resource-pair identity and entered-
quantity currency exchange passed; see its
[evidence](./evidence/2026-09-29-h6a-resource-exchange.json). H6b quote-derived
currency exchange also passed; see its
[evidence](./evidence/2026-09-29-h6b-quote-derived-exchange.json). H7 immediate
assembly passed its bounded schema/probe and regression gates; see [H7 implementation evidence](./evidence/2026-09-29-h7-immediate-assembly.json)
and separate [gross-input feasibility evidence](./evidence/2026-09-29-h7-gross-input-feasibility.json).
H8 bounded timed production passed its integration and scoped regression gates;
see [H8 integration evidence](./evidence/2026-09-29-h8-timed-production-integration.json).
The bounded implementation gates through H8 have passing evidence. H8 physical
cost measurement and H4b5c residual policy remain open. No new domain expansion
is assigned. H0 context compression remains a separate maintenance packet. See the
[accounting handoff](../all-in-accounting/implementation-handoff.md) for packet
limits and selection guidance.

## Baseline conclusion at audit time — 2026-09-26

The later implementation contains substantial working core functionality.
Fresh disposable checks support C1–C4 and important O1–O3 runtime slices.
Retain that work. K1 scheduling, K2 atomic admission, and K3 dead-letter age
retention now pass focused checks. **The core is not ready for a reliability
sign-off:** credential reuse still needs the user's clarified ownership
contract, and full integration and production gates remain.

The next implementation route is [core-handoff.md](./core-handoff.md), K4b–K5.
K4a's permission/use matrix is in the
[credential ownership contract](./credential-ownership-contract.md); it remains
design evidence until K4b probes pass.
The [configuration reference](./core-configuration.md) records current defaults,
limitations, and focused verification commands for smaller-model continuation.
The [2026-09-28 K1–K3 evidence](./evidence/2026-09-28-core-stabilization.json)
records the current source fingerprint and probe results.

The later 2026-09-28 [architecture review](./verification.md#architecture-review--2026-09-28)
reopens named domain planning through the [accounting handoff](../all-in-accounting/implementation-handoff.md).
It corrects stale tree/lifecycle descriptions and the economic-entity target,
without changing core code or claiming new domain runtime verification.

## Scope and source identity

- Astra marker: `9581208` (2026-09-24); following design checkpoint `cb2b64d`;
  audited HEAD `a6626c0cb4aa134ed0bd27346aa7e2ee660260a8` (2026-09-25).
- The redesign-system documents were added after the original marker. Model
  names in commit messages establish handoff intent, not line-level authorship.
- The checkout had 135 dirty entries after removal of one unrelated untracked
  terminal-history artifact. Untracked generators, runtime operations,
  framework SQL, and probes were included in the audit. HEAD alone is not the
  tested implementation.
- SHA-256 over 106 core source/package files:
  `69d0afa558651f7451d6d2c74f3a192077dc937d2e41d1e1d3a552ba6c6cceab`.
  The source fingerprint was unchanged after this audit. The evidence artifact
  describes its construction and includes per-file hashes.
- No core implementation or domain source was changed by this pass. Shared
  generated all-in-one artifacts were refreshed after a stale-output finding.
  Existing unrelated working-tree changes were preserved.

This is a targeted source/contract audit with fresh regression and fault
evidence, not formal verification of every possible interleaving. Earlier
handoffs were routing information; they were not counted as fresh test results.

## Findings and decisions

### F1 — Scheduling horizon and scan cadence disagreed (K1 fixed 2026-09-28)

At the audited baseline, `config/environment.js` defaulted to a 1,800,000ms reconciliation interval.
`gateway/reconciler.js` waits that interval **after a scan completes**.
`gateway/runtime.js` admits hints only within 300,000ms and independently
passes `horizon: "5m"` into `pendingPage`.

Consequently, with an empty queue and no new client activity: a startup scan
at minute 0 skips a task due at minute 10; the next scheduled scan starts
after minute 30. That task can enter the queue twenty minutes late. Other
creation times, page limits, contexts, and saturation affect the delay.
This is a source-derived execution trace, not a measured thirty-minute test.
At the 2026-09-26 audit, positive tests used short/manual reconciliation
scenarios and did not close this default-configuration gap.

Changing only the enqueue horizon option also left query selection at five
minutes. On 2026-09-28, K1 changed the default cadence to one minute, rejects a
configured interval at or above the five-minute horizon, shares the horizon
constant between runtime admission and query formatting, immediately follows
an admitted full page, and backs off after deferral. The new fake-clock probe
and environment probe pass. The full disposable runtime probe also passes,
closing F1; backlog and multi-context lateness remain workload-dependent.

### F2 — Queue admission exceeded its configured cap (K2 fixed 2026-09-28)

At the audit baseline, `gateway/queues/bullmq.js` counted jobs and renewed a 30-second
distributed lock, then calls `queue.add` in a separate Redis operation. A
producer can stop between that final check and the add. Lock heartbeats do
not execute while the process is stopped.

The audit used a disposable Redis and two independent producer processes:

1. Configure `maxLiveHints=2`, `receiptReserve=0`.
2. Pause producer A with `SIGSTOP` immediately after its last lock check.
3. Wait for its actual Redis TTL to expire (no forced deletion of the lock).
4. Producer B admits two distinct live hints.
5. Resume A; its previously authorized add succeeds.

**Observed: three live hints with a limit of two.** The reproduction took
32.066 seconds and exited successfully because it asserted the defect.
[Audit specimen](./evidence/admission-lock-expiry.cjs), runnable from repo root:

```bash
node designs/rebase-system/evidence/admission-lock-expiry.cjs
```

This reproducer captures the pre-fix Linux process-pause failure. K2 removes
the separate lock/count protocol and checks the cap inside the same BullMQ Lua
script that stores the job. `npm run probe:admission` pauses one producer
before insertion, fills the cap from another process through delayed and
prioritized insertion paths, then confirms the resumed producer is deferred
and the count remains two. It also verifies duplicates at capacity. The
adapter is pinned to BullMQ 6.2.0 and checks its script shape; Redis Cluster is
not certified. K2 passes the queue and full runtime probes, including receipt
reserve, Redis outage recovery, and durable rediscovery.

### F3 — Dead-letter jobs could accumulate indefinitely (K3 fixed 2026-09-28)

At the audit baseline, `deadLetter()` added jobs to `operations-dead` with `removeOnComplete`.
Repository consumers handle `operations`, while no dead-letter consumer or
pruner is registered. The retained jobs therefore remain waiting; completion
retention does not apply to them. Source tracing found no alternate pruning
path. This audit did not run a large accumulation/memory benchmark.

K3 applies a 30-day waiting-job retention to the state actually used by the
dead-letter queue. A startup pass and one-minute timer each remove up to 1,000
expired records, using BullMQ `clean` on the waiting list. The focused queue
probe covers repeated records from two producers, batched deletion, and
cleanup after restart; the runtime probe confirms the SurrealDB failure
outcome remains after its Redis diagnostic expires. This is an age bound, not
a hard count or memory bound. SurrealDB remains the source of failed and
ambiguous task truth.

### F4 — Credential tables exist but do not meet the clarified reuse contract (K4)

`framework/authentication.surql` already contains the two typed tables
`rebase_email_delivery_config` and `rebase_sms_delivery_config`. They and all
their credential fields use native `PERMISSIONS NONE`. Their current shape has
no owner/use permissions. The compiler treats framework tables as system
tables and skips generated ownership/RLS for them. Putting a row there does
not make `rebase_group:root` its owner or grant a logged-in root-group member
access through record authentication.

`gateway/authentication.js` resolves
`rebase_authentication_delivery_policy:default`, then atomically stores a
challenge hash/revision/nonce and an encrypted delivery task. The worker
rechecks expiry, single use, identity/principal revisions, and nonce before
decrypting. Those protections and the anonymous endpoint boundary are sound
choices to retain. Ordinary email test operations separately reference
`email_brevo_config`, so broad reusable credentials are not yet consolidated.

User correction: platform and BYOC configurations use the same two credential
families. Developers supply ownership, provider fields, and binding. There is
no request for automatic provisioning, policy hierarchies, extra provider
registries, or a new anonymous table API. K4 makes this small boundary explicit.

### F5 — Personal-account identity correction belongs to domain design

At `9581208`, `designs/all-in-accounting/blueprint.md` already required books
with an organization perspective, `(book, treasury, currency)` treasury
accounts, and `(book, operating_unit, resource)` stock accounts. The current
core accounting schema implements those requirements and validates matching
book/organization dimensions. This mismatch with the new user clarification
was inherited from the earlier design; it is not evidence of executor invention.

The framework's generated `owned_by` already permits `rebase_user | rebase_group`.
That authorization owner does not remove the domain's additional mandatory
book/organization fields. Personal treasury/stock/tax ownership must use the
existing user identity when domain design resumes. Preserve organization as
its own identity; do not substitute an authorization group for an economic
organization or require users to create a personal organization.

The current tax table's organization references identify authority/jurisdiction;
they are not a field named personal owner. Revisit those roles explicitly with
the domain model, instead of mechanically removing every organization reference.
No accounting/CRM/HRM/logistics source was edited in this audit.

### F6 — Status documents and generated artifacts had drifted (corrected)

The overview stopped around unverified O2b while the detailed plan claimed
O2s/O3l and accounting A2d. The plan's final checkpoint still mentioned only
A2a. The production-readiness file retained obsolete Hono/SQS/repeat-schedule
claims despite a historical disclaimer. These were contradictory status
summaries, not a reason to throw away the implementation.

Fresh runtime evidence supersedes the blanket assertion that O2b is untested.
At the time of this audit it did not close F1–F3 or every production/provider
gate; the 2026-09-28 K1–K3 update closes those three focused packets. Entry
documents now route through this audit and the bounded core handoff. Long
chronological records remain labeled historical; domain extension is deferred.

`npm run check:all-in-one` initially failed with stale generated schema. A
fresh temporary compile showed exactly 117 added schema lines, covering
`rebase_webhook_receipt` and its lifecycle fields/indexes; no schema lines
were removed and no HTTP-binding differences appeared. Native validation
passed. `npm run build:all-in-one` refreshed generated artifacts and the
subsequent check passed. Business source was unchanged.

## Fresh verification

Machine-readable commands, outputs, durations, and source hashes:
[2026-09-26 audit evidence](./evidence/2026-09-26-core-audit.json).

| Check | Result | Measured seconds / scope |
|---|---|---|
| Compiler contracts | Pass | 1.219; deterministic compiler/API and invalid declarations. |
| Environment profile | Pass | 0.886; validation and native env-file precedence. |
| Authentication unit | Pass | 0.334; injected store/provider boundary. |
| Architecture | Pass | 1.837; fixed principals, reference/event scope, sync rollback. |
| Security/audit integration | Pass | 3.456; disposable DB, readers/groups/revocation/cycles, both select policies. |
| Full runtime fixture | Pass | 55.785; actual disposable DB/Redis, mock providers, migration batches/restart, leases, process recovery, receipts. |
| Typed ordering | Pass | 87.084; 113 mutation checkpoints, 1,308 reads, 101 rejection snapshots. |
| Multiple positions | Pass | 204.408; 221 checkpoints, 1,084 reads, 12 rejections, all 24 insertion permutations and linked deletions. |
| Boundary/derived/required/causal fixtures | Pass | 47.585 combined; 5,442 algebra sequences, 61,386 folds, transactional downstream rollback and cleanup. |
| Quick temporal integration | Pass | 42.305; 36 randomized mutations plus deterministic/privacy/contention cases. |
| Queue unit / adapters | Pass | 0.357 / 0.292; envelope/default contracts and mocked provider mapping. |
| Test artifact check / native validation | Pass | 0.751 / 0.277. |
| All-in-one artifact check | Failed, then repaired | 0.938 initial; refresh 0.840; recheck 0.823. |
| Fresh all-in-one compile / native validation | Pass | 0.522 / 0.490; temporary output used to diagnose stale artifacts. |
| Admission fault experiment | Defect reproduced | 32.066; real lock expiry and process pause. |

Some independent checks ran concurrently. These timings are single local
samples, not comparative performance benchmarks. The test matrices are much
cheaper than new large load experiments, and no unchanged probe was repeated
solely to obtain another green result.

## What remains unverified

- Full `npm run verify` against a final repaired snapshot; the current script
  also omits the positions probe, so its success alone would not cover that
  path. No full domain-suite acceptance was asserted in this pass.
- K4 ownership/use matrix with shared and tenant credential fixtures.
- Live email/SMS/payment/storage semantics, provider ambiguity resolution,
  credential rotation, external outages, and a production migration rollout.
- Generalized numeric key types, full-width numeric SDK transport, physical
  large-dataset capacity, and representative resource/throughput measurements.

These are explicit remaining gates. No broad claim of hallucination, complete
correctness, production readiness, or physical million-row capacity follows
from the audit.
