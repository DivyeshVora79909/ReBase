# Production Readiness Report

## Reader and custom-index continuation — 2026-10-07

The [developer blueprint](designs/rebase-system/developer-blueprint.md) documents
single-principal readers, private custom identity indexes, and explicit tenant/
owner analytics. Use the [current verification](designs/rebase-system/reader-index-verification.md)
for this shared-framework change. Earlier results below retain their original
source snapshots and do not establish deployment or populated-schema migration.


## Accounting extension — 2026-10-08

The active [accounting profile](designs/all-in-accounting/README.md) adds validated
adjustment-note groups, tax cash/credit offsets, explicit non-invoice claims,
inline charges and unit-safe opt-in analytics on the existing tree engine.
[The extension contract](designs/all-in-accounting/extension-contract.md) defines
those capabilities. [Current acceptance](designs/all-in-accounting/extension-verification.md)
is scoped to the local compiled source and its disposable database checks.
The compiler/runtime now enforce 1–16 business-key components.

The [October 5 normalization evidence](designs/rebase-system/evidence/2026-10-05-accounting-normalized-acceptance.json)
and older H1–H8 results below describe their original source snapshots. They do
not certify this API, a populated database conversion or production capacity.

## Tenant/tree baseline — 2026-10-05

**Tenant/tree backend T0–T6 passed; ready for lead review.** The
[execution handoff](designs/rebase-system/tenant-tree-handoff.md) and
[verification evidence](designs/rebase-system/evidence/2026-10-05-tenant-tree-verification.json)
record commands, source/build hashes, versions, archived output and resolved failures.

| Gate | Result |
| --- | --- |
| Three profile builds and full `npm run verify` | Passed; 1,006.086 seconds for verification, including native validation and all 26 developer-tool tests. |
| Full `npm run verify:accounting` | Passed in 694.793 seconds, including delivery taxes, existing tax/withholding paths, returns/refunds, exchange and production. |
| Positions and mocked Razorpay refunds | Passed in 291.274 and 1.028 seconds respectively. |
| Changed/new JavaScript | All 84 files passed syntax checks. |

Aggregate views preserve their declared owner/reader policy. Managed outputs
follow dependency order, and live subscriptions recover after failed initial
attachment. The final source differs from the retained build/backend passes
only in the isolated H7 feasibility probe, which those commands do not load;
the complete accounting suite passed after that repair.

SurrealDB 3.3.0 produced duplicate rows in one indexed ID-order source scan.
Affected snapshots use `WITH NOINDEX ORDER BY id`; the reproduction and limited
workaround are documented without a broader engine or performance claim.
MetaSol remains unchanged and needs its separate tenant migration. Live providers,
production deployment/data migration and representative capacity remain outside
this acceptance. The 2026-10-03 results below retain their original scope.

## Historical verified baseline — 2026-10-03

**Verified for the requested scope:** developer tools, local SurrealDB
consistency, and the delivered MetaSol frontend. The
[review evidence](designs/rebase-system/evidence/2026-10-03-redesign-verification.json)
records commands, source fingerprints, logs and exclusions.

| Check | Result |
| --- | --- |
| Compiler and exports | All three profile checks, accounting native schema validation, compiler/environment probes, and exact five-file public schema export passed. |
| Database and runtime | Accounting core (including invoice timestamp/rollback regressions), credential permissions, authentication and disposable SurrealDB/Redis runtime checks passed. |
| Developer tools | Final workbench/public-schema suite: **26 passed**. |
| Frontend | Full baseline: **26 native/unit + 28 browser tests passed**. After the invoice fix: focused native and browser invoice checks plus a fresh production build passed. |

The review fixed same-instant invoice settlement and a build path that could
overwrite an authoring file through a hard-linked output. It refreshed the
missing generated client schemas and corrected stale handoff/status text.
The final frontend checks cover partial/full settlement and rejection rollback;
the earlier complete suites were not rerun after those focused edits.

The user excludes live email/SMS/payment credentials and has no data to migrate.
Redis admission code matches the previously verified atomic implementation;
fresh runtime integration passed, so no high-concurrency load run was needed.
These results do not claim production capacity. Further frontend tax,
returns/refunds, administration/onboarding, CRM and HRM features remain in the
[deferred-work map](designs/frontend/deferred-work.md).

Use the [core audit](designs/rebase-system/core-audit.md),
[accounting handoff](designs/all-in-accounting/implementation-handoff.md),
[frontend verification](designs/frontend/verification.md), and
[configuration reference](designs/rebase-system/core-configuration.md) for
scope and continuation. H4b5c is resolved for current invoice tax paths; H8's
historical transaction counters do not measure physical storage costs.

<details>
<summary>Archived report from before the one-shot runtime cutover (superseded)</summary>

The following historical assertions describe an older checkout. Hono, SQS,
repeat schedules, platform process-key adapters, and its production bearer
limitation do not describe the current implementation. Its verdict and commands
are preserved as history; use the current audit above for decisions.

Original report: updated after the named-adapter runtime reboot and canonical
environment-profile work. Tested with Node `22.23.2`, SurrealDB `3.2.0`,
disposable Redis/SurrealDB, injected transports, and an injected AWS SQS client.

## Verdict

**CONDITIONALLY READY** for development and integration testing. The compiler, SurrealDB security framework, named Brevo/S3/Razorpay adapters, BullMQ kernel, schedules, Razorpay webhooks, reconciliation, startup/shutdown, and SQS port pass deterministic or disposable probes. Production deployment remains blocked by untested live service credentials/infrastructure and the generated-event production identity limitation below.

## Architecture

| Component    | Responsibility                                                                                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compiler     | Classifies SurrealQL material, discovers principals/effects, generates authorization/audit/references/views/lifecycle/events, validates handlers, and emits `schema.surql`, `runtime-contracts.json`, and handlers. |
| SurrealDB    | Authentication, authorization, strict schema/reference validation, audit/change logs, typed effects, lifecycle truth, sync rollback, schedule cursors, and webhook ordering facts.                                  |
| Hono kernel  | Authenticated wakes, handler lookup, conditional leases, token-fenced finalization, bounded patches, webhook correlation, and readiness.                                                                            |
| BullMQ/Redis | Three transport lanes (`task`, `schedule`, `webhook`), delay, retry, stalls, concurrency, deduplication, and durable lane-specific dead letters.                                                                    |
| Reconciler   | Startup and periodic scans of configured namespace/database contexts; republishes executable locators without querying queue membership.                                                                            |
| Adapters     | Static named Brevo, S3-compatible storage, Razorpay order, Razorpay webhook, and platform Resend functions. Runtime contracts receive only declared functions.                                                           |
| Configuration | One explicit `.env.*` profile is resolved at each executable boundary; tenant service credentials remain in strict SurrealDB records.                                                                                  |

## Coverage Matrix

| Area                 | Scenarios                                                                                                                                                                                                                   | Status                        |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Compiler             | deterministic build/check, context-neutral contracts, lifecycle generation, schedule typing, handler discovery/aliases, missing/duplicate/unknown handlers, collisions, mutable inputs, writable outputs, webhook contracts | **PASS**                      |
| SurrealDB framework  | typed authentication identities/challenges, password-independent access, ownership/delegation, parent DAG, readers, references, row/field permissions, audit/change logs, views, UUIDv7, sync snapshot/rollback | **PASS**                      |
| Async kernel         | record-user creation, atomic claim, duplicate delivery, retries, terminal failures, ambiguous-result reconciliation, cancellation, stale-token fencing, patch allowlists, reference-scoped loads                            | **PASS**                      |
| BullMQ               | all lanes, internal job IDs, delay/retry, durable DLQs, readiness, timing restoration from SurrealDB                                                                                                                        | **PASS**                      |
| SQS port             | all-lane API shape, delay clamping, receive counts, visibility retry, invalid locator DLQ, retry exhaustion, scheduling, health                                                                                             | **PASS** with injected client |
| Scheduling           | cursor initialization, fresh unlinked UUIDv7 occurrences, concurrent schedulers, repeat exhaustion, coalesce/skip/all misfires, cancellation, lost Redis delayed job recovery                                               | **PASS**                      |
| Webhooks             | raw-body HMAC, signed route capsule, context/config correlation, event dedupe, reverse ordering, table correlation, bad signatures                                                                                         | **PASS** with injected payloads |
| HTTP/startup         | liveness/readiness, body/content limits, HMAC/bearer policy, context allowlist, real child process, missing config, port conflict, unavailable Redis, production static-adapter startup, SIGTERM                         | **PASS**                      |
| Multi-context        | concurrent connection deduplication, failed creation eviction, idle-safe tracking, configured context allowlist                                                                                                             | **PASS**                      |
| Environment profiles | file parsing, precedence, canonical names, neutral/complete compiler profiles, stale profile-bound checks, profile-only server startup, dynamic workbench context contract, visualizer configuration                         | **PASS**                      |
| Live services/cloud  | Live Brevo, Resend, Razorpay Test Mode, S3-compatible storage, real AWS SQS, managed Redis/Valkey/Dragonfly, Surreal Cloud                                                                                                   | **OPT-IN / UNTESTED**         |

## Remaining Production Blockers

1. **Live services and cloud infrastructure are unverified.** Run opt-in checks with scoped test credentials for Brevo, Resend, Razorpay Test Mode, the selected S3-compatible service, AWS SQS, managed Redis/Valkey, and the target SurrealDB deployment. Deterministic probes verify request mapping and error semantics but cannot establish vendor account policy or network behavior.
2. **Internal production identity is HMAC-only in this repository.** Timestamped raw-body HMAC is enforced and bearer auth is development-only by default. Add workload identity or mTLS at the deployment edge where required.
3. **Generated SurrealDB events currently use a static infrastructure bearer addressed to the deployment binding.** SurrealDB `3.2.0` has no HMAC signing function available to the event query, so generated `http::post` calls cannot produce the runtime's timestamped HMAC directly. The production runtime rejects bearer wakes; therefore production needs a private trusted proxy that validates and rotates the event bearer, then forwards HMAC/workload identity/mTLS, or a future SurrealDB signing capability. Direct production event-to-runtime delivery is not supported by the current binding.

## Commands

```text
npm run build
npm run check
surreal validate build/test/schema.surql
npm run probe:environment
npm run probe:compiler
npm run probe:architecture
npm run probe:queues
npm run probe:runtime
npm run probe:adapters
npm run probe
npm run verify
```

The verification suite uses disposable data and does not send real email, create cloud objects, or mutate real AWS queues.

</details>
