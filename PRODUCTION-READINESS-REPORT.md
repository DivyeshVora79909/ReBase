# Production Readiness Report

Updated after the named-adapter runtime reboot and canonical environment-profile work. Tested with Node `22.23.2`, SurrealDB `3.2.0`, disposable Redis, disposable in-memory SurrealDB, deterministic injected service transports, and an injected AWS SQS client.

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
| SurrealDB framework  | auth/invites, ownership/delegation, parent DAG, readers, references, row/field permissions, audit/change logs, views, UUIDv7, sync snapshot/rollback                                                                        | **PASS**                      |
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
