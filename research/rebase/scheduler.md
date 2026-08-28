# Schedules and Reconciliation

Status: adopted scheduler policy

This document owns time-based triggers, lost-wake recovery, context discovery,
and scheduler alternatives. The normal effect/handler contract is in
[`architecture.md`](./architecture.md) and [`runtime-dispatch.md`](./runtime-dispatch.md).

## Schedules are ordinary effects

A schedule is an input adapter, not a second job architecture. A schedule record
contains the validated effect inputs, `owned_by`, UTC five-field cron/repetition
policy, skip/misfire policy, next due time, and schedule lifecycle. At a due time
the scheduler:

1. copies the input fields and `owned_by` into a fresh record in the same effect
   table;
2. clears schedule-only fields and sets the new record to `pending`;
3. lets SurrealDB generate a fresh occurrence record ID;
4. lets the normal async event, queue, handler, webhook, and reconciliation path
   process the occurrence.

The occurrence does not store a template reference or require a compound
occurrence key. It is equivalent to a new user submission at that time. Repeated
alarms are repeated submissions; provider idempotency or an effect-specific
policy decides whether repetition is safe or intentional.

The new record copies the schedule's `owned_by`, then passes ordinary row
authorization and visibility rules. A scheduler is an actor performing work on
behalf of that owner, not a bypass around the data model.

## Durable truth and disposable runtime state

SurrealDB schedule/effect records are authoritative. The runtime may keep only
rebuildable state such as:

```text
context -> dirty, next_wake_at, empty_backoff, last_scan_at, failures
```

BullMQ delayed jobs/job schedulers are the primary timing mechanism. Rebuildable
in-memory timing indexes are optional optimizations only; reconciliation
restores lost delayed jobs from durable cursors after restart. A managed
external scheduler can replace BullMQ later through the scheduling port, but
should wake the platform rather than write tenant rows through an unauthenticated
boundary.

## Wake delivery

An async database event sends a best-effort wake containing only:

```json
{ "namespace": "...", "database": "...", "id": "table:generated-id" }
```

The runtime coalesces duplicate wakes for one context and publishes the locator
to the managed queue. Wake delivery is an accelerator, not a correctness source:
the queue can duplicate or lose a message, and the process can crash between
wake receipt and publication.

The internal endpoint requires deployment authentication, exact-body signing or
mTLS/workload identity, replay protection, strict limits, and a private network
where possible. Tenant credentials are not reused.

### Engine observations behind wake delivery

On SurrealDB 3.2.0, an `ASYNC` event successfully delivered
`session::ns()`, `session::db()`, and the current record ID to a local HTTP
receiver after commit. With `RETRY 2`, an endpoint returning HTTP 503 twice
received three requests within milliseconds. Database-event retry is therefore
at-least-once wake delivery, not delayed scheduler backoff. See
[`../surrealdb/async-events.md`](../surrealdb/async-events.md).

Parameterized top-level context switching worked:

```surql
USE NS $namespace DB $database;
SELECT * FROM send_brevo_email;
```

The same `USE` cannot be executed dynamically inside a `FOR` loop. Context
enumeration therefore needs bounded top-level composite statements, not one
dynamic all-databases loop.

## Reconciliation

Reconciliation is a periodic correctness sweep. For each selected
namespace/database, a generated SurrealQL script queries every compiled async
effect table for direct IDs whose state is still executable or recoverable:

```text
unleased and due tasks
ambiguous provider outcomes whose wake deadline is due
scheduled sources with unfinished cursors
```

It republishes `{ namespace, database, id }` to the same queue. The count of
typed effect tables is not a reason to centralize business records; direct ID
access and per-table indexes are the intended path. The generated query should
remain bounded and use state/due indexes.

Do not ask SQS whether an exact locator is already queued. Queue membership is
not a reliable correctness query. Duplicate enqueue is expected and is handled
by conditional claims, terminal-state no-ops, stable provider idempotency, and
provider reconciliation.

## Deadlines and optional timing strategy

The correctness values are explicit deadlines:

```text
next scheduled run
next retry/repair eligibility
provider follow-up deadline
next reconciliation sweep
```

The runtime may coalesce these into `next_wake_at = min(deadlines)` and use a
min-heap for active contexts. Empty contexts can use bounded exponential backoff
with jitter; due work should be drained in bounded batches. A periodic sweep is
still required for lost wakes and process restarts.

These values are operational tuning parameters, not schema semantics. Measure
them against deployment workload rather than copying fixed constants from a
probe.

## Calendar and outage policy

Use an established Node scheduler/parser for calendar expressions and time
zones. Do not implement general cron arithmetic from remainders in SurrealQL.
Fixed-duration schedules may use native datetime/duration arithmetic.

Outage catch-up is explicit product policy:

```text
skip missed runs
run one catch-up
run all missed runs up to a strict cap
```

Do not infer this from averages, variance, burst scores, or activity history.

## Context discovery

The hot path is wake-driven. Startup and repair use bounded topology discovery:

1. enumerate known namespaces/databases;
2. generate bounded top-level `USE NS ... DB ...` composite statements;
3. query declared schedule/effect tables in bounded batches;
4. enqueue returned direct locators.

SurrealDB does not permit dynamic database switching inside a `FOR` block. A
single loop cannot enumerate root topology and then execute `USE` for every
database. Composite batches and bounded concurrency are the portable strategy.

Catalog listing is cheap at the measured scale, but data scans across thousands
of contexts still belong to startup/repair, not every wake.

## Rejected scheduler model

An earlier alternative proposed `edge_job`, `edge_cron`, `edge_log`, leases,
attempt counters, outbox-like dispatch state, and a min-heap as the primary
architecture. Its measurements remain useful for engine wake/retry behavior in
[`../surrealdb/async-events.md`](../surrealdb/async-events.md), but ReBase does
not adopt a central generic job model:

- typed effect tables remain the business source of truth;
- managed queues own transport retry/visibility/redrive;
- effect records keep only user-facing business state;
- schedules create ordinary effects instead of generic jobs;
- reconciliation filters pending/recoverable typed rows and republishes IDs.

The richer lease/attempt model may be reintroduced only if a provider or queue
failure mode demonstrates that managed transport plus state-driven handlers is
insufficient.

The rejected model’s useful lessons are retained here:

- explicit deadlines (`available_at`, `next_run_at`, lease expiry) are better
  scheduler inputs than statistical activity scores;
- `next_wake_at = min(all known deadlines)` is a sound timing reduction;
- a min-heap with coalesced dirty contexts is a valid runtime optimization;
- calendar parsing belongs in an established Node library, not SurrealQL;
- missed-run behavior must be an explicit skip/one-catch-up/capped-catch-up
  policy;
- queue membership is never an exact correctness query.
