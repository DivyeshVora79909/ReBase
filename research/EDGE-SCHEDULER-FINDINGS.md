# Edge Scheduler Findings

Status: Superseded alternative. The implemented architecture uses ordinary
table-keyed effect records and an external queue; see
[../ARCHITECTURE.md](../ARCHITECTURE.md). The measurements below are retained
for scheduler tradeoff analysis.

This document evaluates a self-contained, multi-namespace edge scheduler against
SurrealDB 3.2.0. The probes used isolated in-memory databases on 2026-08-18.

The target architecture has no tenant registry or administration database.
SurrealDB remains the durable source of truth. The runtime keeps only disposable
scheduling state that can be rebuilt after a restart.

## Decision

Keep three operational tables in each application database:

- `edge_job` is the durable work item, webhook receipt, result, retry, and lease.
- `edge_cron` is the durable recurring schedule.
- `edge_log` is append-only execution history.

Remove the separate outbox only after `edge_job` itself becomes the recoverable
dispatch source. The external queue is then a wake-up and delivery accelerator,
not the authoritative job store.

Use asynchronous database events to send best-effort wake hints to the runtime.
Use deterministic deadlines and a priority queue to decide when to scan. Do not
use averages, variance, standard deviation, or burst scores for correctness.

## Confirmed SurrealDB Behavior

### Async HTTP wake events work

The following event successfully delivered the current namespace, database, and
record ID to a local HTTP server after the creating transaction completed:

```surql
DEFINE EVENT wake ON TABLE edge_job
  ASYNC RETRY 2 MAXDEPTH 0
  WHEN $after.status = 'pending'
  THEN http::post('http://127.0.0.1:18002/ping', {
    ns: session::ns(),
    db: session::db(),
    id: <string>$after.id
  });
```

`session::ns()` and `session::db()` retained the expected application database
context inside the asynchronous event.

SurrealDB must allow both the HTTP function and the target network address. A
production instance should use a narrow `--allow-net` rule and a private wake
endpoint.

### Async retries are immediate and duplicate

With `RETRY 2`, an endpoint that returned HTTP 503 twice received three requests
within milliseconds. Therefore:

- wake delivery is at least once;
- the endpoint must be idempotent and aggressively coalesce duplicates;
- event retry is not delayed job retry or scheduler backoff;
- losing every wake must remain recoverable through reconciliation.

The wake payload must contain only routing metadata. It must not contain job
arguments, credentials, records, or provider configuration.

### Parameterized database switching works

SurrealDB accepted parameterized top-level database selection:

```surql
USE NS $ns DB $db;
SELECT * FROM edge_job;
```

A composite RPC can repeat that sequence for several known contexts and returns
one result per statement.

### Database switching cannot run inside `FOR`

SurrealDB rejected `USE NS ... DB ...` inside a `FOR` block. A single SurrealQL
loop cannot enumerate root topology and dynamically query every database.

The runtime must generate repeated top-level statements from its known context
set. Large context sets should be divided into bounded composite batches and run
with bounded concurrency.

## Why Statistical Activity Scores Are The Wrong Primitive

Mean, variance, standard deviation, moments, and burst skew describe historical
arrival patterns. They do not answer the scheduler's correctness question:

> What is the earliest time at which work can become executable?

A single cron due at 03:00 must run at 03:00 even when its database has had no
activity for a month. A burst of 1,000 jobs requires immediate draining, not a
prediction that the burst may continue. Retry and lease expiry are also explicit
deadlines.

The sufficient scheduling values are:

```text
next job available_at
next cron next_run_at
next dispatch retry time
next running lease expiry
next reconciliation deadline
```

The runtime can reduce these values to one scalar without losing meaning:

```text
next_wake_at = minimum(all known deadlines)
```

Statistics remain useful for observability, autoscaling, batch-size tuning, and
rate limiting. They must not decide whether due work is inspected.

## Runtime Scheduler

The runtime keeps an in-memory map keyed by the composite database coordinate:

```text
instance + namespace + database
```

Each value contains only rebuildable state:

```text
dirty
next_wake_at
empty_backoff_ms
last_scan_at
consecutive_failures
```

All contexts are stored in a min-heap ordered by `next_wake_at`. One timer sleeps
until the heap's first deadline. There is no fixed one-minute or two-minute loop
for active scheduling.

### Wake handling

On an async event ping:

```text
dirty = true
next_wake_at = now
empty_backoff_ms = minimum backoff
```

If the context is already scheduled, update its heap position. Thousands of
duplicate pings still produce one pending scan.

### Scan handling

For one database, a bounded query should return:

- due jobs ordered by `available_at`;
- due crons ordered by `next_run_at`;
- the earliest future job deadline;
- the earliest future cron deadline;
- the earliest expired or future lease requiring recovery.

Use indexed predicates and a configurable batch limit. Do not load the first ten
rows and calculate time differences in application code. Select only rows whose
indexed deadline is due, plus one row for each next future deadline.

After a scan:

```text
work found      -> scan again immediately until the bounded batch is not full
future deadline -> sleep until that deadline
empty database  -> exponential backoff with jitter up to a maximum
query failure   -> failure backoff and eventual topology reconciliation
```

Suggested initial values, to be measured rather than treated as constants:

```text
minimum coalescing delay: 100-500 ms
job/cron claim batch:     50-200
empty backoff:            5 s -> 15 s -> 1 m -> 5 m -> 15 m
reconciliation sweep:     2-10 m
```

The sweep is a correctness backstop for lost pings and process restarts. It is
not the main dispatch mechanism.

## Durable Dispatch Without A Separate Outbox

Removing `edge_outbox` is sound only when dispatch is recoverable from
`edge_job`.

The queue message may be duplicated or lost. A scheduler may crash between a
database update and queue publication. The job row must therefore retain enough
state to redispatch safely.

A minimal durable state machine is:

```text
pending -> running -> succeeded
        -> running -> pending at a future available_at
        -> running -> failed
        -> cancelled
```

Required internal fields include:

```text
available_at
next_dispatch_at
attempts
max_attempts
lease_owner
lease_expires_at
idempotency_key
revision
```

The scheduler atomically reserves due pending jobs, publishes queue hints, and
sets a future redispatch deadline. If publication or delivery is lost, the same
job becomes eligible again. If a message is duplicated, the worker's atomic
lease claim allows only one execution.

The JavaScript `Promise` state cannot replace this state machine. Promise state
is process-local, is not queryable by clients, and disappears on restart.

## Cron Semantics

`edge_cron` stores schedule state. Every firing creates an ordinary `edge_job`,
so execution, retries, cancellation, and logs use one pipeline.

Recommended cron fields include:

```text
capability
records
args
enabled
schedule
timezone
next_run_at
last_run_at
concurrency_policy
misfire_policy
max_catch_up
revision
```

When a cron is due, one database transaction must:

1. claim the cron revision or lease;
2. create jobs with a unique key derived from cron ID and scheduled time;
3. advance `next_run_at`;
4. release the cron lease.

Use an established cron parser in Node for calendar expressions and time zones.
Do not implement general cron arithmetic from remainders in SurrealQL. Fixed
duration schedules may use native datetime and duration arithmetic.

Outage catch-up must be explicit policy:

```text
skip missed runs
run one catch-up
run all missed occurrences up to a strict cap
```

Variance must not infer this business policy.

## Permission-Based Operational Tables

Allowing record users to create and inspect jobs can remove ordinary CRUD HTTP
endpoints. It does not mean clients may mutate operational fields.

Compiler-generated permissions should enforce:

- `actor` is derived from `$auth` and cannot be supplied;
- only an authorized capability can be submitted;
- `status`, attempts, leases, result, error, and revisions are server-owned;
- records and args cannot change after dispatch;
- users can select and cancel only jobs they are allowed to access;
- cron creation and mutation require separate capabilities;
- logs are server-created and selectively readable;
- credential values are rejected from raw args.

Worker-time authorization remains mandatory. Access to referenced records may be
revoked after job creation.

Webhook deduplication can be folded into `edge_job` by using a webhook job kind
and a unique provider event key. The job then acts as both receipt and execution
record.

## Design Operations And Global Adapters

Separate application behavior from provider integration:

```text
design operation
  -> validates args and declared record slots
  -> authorizes and resolves records
  -> prepares a typed adapter invocation

global adapter
  -> validates adapter input
  -> resolves secret references
  -> calls the provider SDK
  -> returns a bounded result
```

Example prepared invocation:

```js
{
  adapter: "email.sendCampaign",
  version: 1,
  input: {
    configSecretRef: "secret:brevo-primary",
    recipients: ["person@example.com"],
    subject: "Invoice",
    html: "..."
  }
}
```

The operation may choose only adapters declared at compile time. The global
adapter never receives an unrestricted database connection. Preserve the
current rule that design code receives bounded, authorized records rather than
privileged query access.

## Topology Discovery

The runtime does not need to query every database on every scheduling pass.

Use three discovery paths:

1. async wake hints add or refresh active contexts immediately;
2. startup discovery rebuilds contexts after a restart;
3. infrequent reconciliation finds lost pings and topology changes.

Topology discovery requires at least two phases because root results cannot be
used to execute dynamic `USE` statements inside the same query:

```text
INFO FOR ROOT
  -> generate bounded INFO FOR NS composite batches
  -> generate bounded database marker/job/cron composite batches
```

The instance-scaling study shows catalog enumeration is inexpensive, but data
queries across thousands of databases still need bounded batching and should
remain a recovery path rather than the hot path.

## Final Architecture

```text
record user creates edge_job or edge_cron
  -> database permissions validate the write
  -> async event sends best-effort wake hint
  -> scheduler coalesces the database context in a deadline heap
  -> scoped composite query claims due jobs and advances due crons
  -> queue receives context-rich delivery hints
  -> worker atomically leases the job and reauthorizes records
  -> design operation prepares a global adapter invocation
  -> adapter performs the external effect
  -> worker persists terminal or retry state and appends edge_log
```

This design is operationally stateless: all correctness state remains in the
tenant application databases, while runtime maps, heaps, caches, and queue
messages may be lost and rebuilt.
