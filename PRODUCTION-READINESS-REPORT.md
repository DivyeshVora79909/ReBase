# Production Readiness Report

Updated after the runtime/compiler reboot. Tested with Node `22.23.2`, SurrealDB `3.2.0`, disposable Redis, disposable in-memory SurrealDB, local providers, and an injected AWS SQS client.

## Verdict

**CONDITIONALLY READY** for local development and integration testing. The compiler, SurrealDB security framework, BullMQ kernel, schedules, local webhooks, reconciliation, startup/shutdown, and SQS port pass disposable probes. Production deployment remains blocked by absent real Brevo/object-storage provider adapters and untested real Redis/SQS/Surreal Cloud infrastructure.

## Architecture

| Component    | Responsibility                                                                                                                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compiler     | Classifies SurrealQL material, discovers principals/effects, generates authorization/audit/references/views/lifecycle/events, validates handlers, and emits `schema.surql`, `runtime-contracts.json`, and handlers. |
| SurrealDB    | Authentication, authorization, strict schema/reference validation, audit/change logs, typed effects, lifecycle truth, sync rollback, schedule cursors, and webhook ordering facts.                                  |
| Hono kernel  | Authenticated wakes, handler lookup, conditional leases, token-fenced finalization, bounded patches, webhook correlation, and readiness.                                                                            |
| BullMQ/Redis | Three transport lanes (`task`, `schedule`, `webhook`), delay, retry, stalls, concurrency, deduplication, and durable lane-specific dead letters.                                                                    |
| Reconciler   | Startup and periodic scans of configured namespace/database contexts; republishes executable locators without querying queue membership.                                                                            |
| Providers    | Local deterministic email/storage examples only. Production adapters remain separate work.                                                                                                                          |

## Coverage Matrix

| Area                 | Scenarios                                                                                                                                                                                                                   | Status                        |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Compiler             | deterministic build/check, context-neutral contracts, lifecycle generation, schedule typing, handler discovery/aliases, missing/duplicate/unknown handlers, collisions, mutable inputs, writable outputs, webhook contracts | **PASS**                      |
| SurrealDB framework  | auth/invites, ownership/delegation, parent DAG, readers, references, row/field permissions, audit/change logs, views, UUIDv7, sync snapshot/rollback                                                                        | **PASS**                      |
| Async kernel         | record-user creation, atomic claim, duplicate delivery, retries, terminal failures, ambiguous-result reconciliation, cancellation, stale-token fencing, patch allowlists, reference-scoped loads                            | **PASS**                      |
| BullMQ               | all lanes, internal job IDs, delay/retry, durable DLQs, readiness, timing restoration from SurrealDB                                                                                                                        | **PASS**                      |
| SQS port             | all-lane API shape, delay clamping, receive counts, visibility retry, invalid locator DLQ, retry exhaustion, scheduling, health                                                                                             | **PASS** with injected client |
| Scheduling           | cursor initialization, fresh unlinked UUIDv7 occurrences, concurrent schedulers, repeat exhaustion, coalesce/skip/all misfires, cancellation, lost Redis delayed job recovery                                               | **PASS**                      |
| Webhooks             | raw-body HMAC, timestamp replay bound, provider account match, event dedupe, reverse ordering, table correlation, bad signatures                                                                                            | **PASS** for local adapter    |
| HTTP/startup         | liveness/readiness, body/content limits, HMAC/bearer policy, context allowlist, real child process, missing config, port conflict, unavailable Redis, production local-provider rejection, SIGTERM                          | **PASS**                      |
| Multi-context        | concurrent connection deduplication, failed creation eviction, idle-safe tracking, configured context allowlist                                                                                                             | **PASS**                      |
| Real providers/cloud | Brevo, object storage, real AWS SQS, managed Redis/Valkey/Dragonfly, Surreal Cloud                                                                                                                                          | **UNTESTED**                  |

## Remaining Production Blockers

1. **Production provider implementations are absent.** `gateway/providers/local.js` is explicitly development-only; production startup rejects it. Implement and test real Brevo and storage adapters, including provider-native idempotency and signatures.
2. **Cloud infrastructure is unverified.** Test the SQS port against disposable AWS/LocalStack-compatible queues, BullMQ against the selected managed Redis/Valkey service, and connection behavior against the target SurrealDB deployment.
3. **Webhook context routing is deployment-specific.** Single-context deployment is built in; multi-context webhook deployments must supply a trusted `resolveWebhookContext` derived from verified provider/account configuration, never payload tenant IDs.
4. **Internal production identity is HMAC-only in this repository.** Timestamped raw-body HMAC is enforced and bearer auth is development-only by default. Add workload identity or mTLS at the deployment edge where required.
5. **Generated SurrealDB events currently use a static infrastructure bearer addressed to the deployment binding.** SurrealDB `3.2.0` has no HMAC signing function available to the event query, so generated `http::post` calls cannot produce the runtime's timestamped HMAC directly. The production runtime rejects bearer wakes; therefore production needs a private trusted proxy that validates and rotates the event bearer, then forwards HMAC/workload identity/mTLS, or a future SurrealDB signing capability. Direct production event-to-runtime delivery is not supported by the current binding.

## Commands

```text
npm run build
npm run check
surreal validate build/test/schema.surql
npm run probe:compiler
npm run probe:architecture
npm run probe:queues
npm run probe:runtime
npm run probe
npm run verify
```

The verification suite uses disposable data and does not send real email, create cloud objects, or mutate real AWS queues.
