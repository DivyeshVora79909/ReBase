# Bounded external work

Source 0.12 implements the experimental `effect-demo` worker against an independent
local fake provider. Business changes and immutable intent commit together.
Provider facts commit before a separate ordinary domain application. The
[G5c checkpoint](../research/39-ingress-recovery-implementation.md) records signed
ingress and recovery acceptance; [G5b](../research/38-fenced-worker-implementation.md)
retains the delivery evidence;
the last packaged deployment remains 0.6.0.

```sh
python3 -B tools/effects_worker.py --binary path/to/rebase-next --out target/effect-worker-run
python3 -B tools/effects_ingress.py --binary path/to/rebase-next --out target/effect-ingress-run
```

The literal example creates Account balance 12, then atomically changes it to 10
and creates Dispatch units 3. Provider success applies to the current Account,
producing 7. If balance became 2 before application, the nonnegative invariant
rejects subtraction: balance stays 2, the success fact remains durable, and
application becomes `blocked`. Authorized repair to 5 and explicit application
retry produce 2 once, without another submission.

## Model and request

Select `--model effect-demo` before every executable command against this store.
`model public` declares requests, typed outcomes and permitted application fields.
The `atomic-intent` fixture provides ordinary Account/Dispatch commands.

Account (101) has a canonical integer `balance`, bounded to one million in
magnitude, with a terminal nonnegative invariant. Dispatch (205) has immutable
`account`, positive `units` up to one million, `execute_at` and `not_after`.
All four fields are required; schedule fields accept canonical millisecond
strings or `null`. Due defaults to creation; expiry defaults to sixty seconds
later. Explicit due is within twenty-four hours before/after creation; expiry
is later than creation/due and at most twenty-four hours after creation.
Claim/start require `execute_at <= now < not_after`.

Create Dispatch through `records.mutate`, with ordinary Create/reference Read
and current Account Update permission. Final request, target, requester/credential
epoch, action version and fixed `fake-account-1` identity are frozen. Replay
precedes allocation/capacity charging. Committed `executions` entries contain
`execution_id`, `source` and `target`, subject to current target Read. The provider
key is execution UUID plus action slot 1. Source deletion/reuse and receipt
archive cannot replace it. Every retained execution pins its Account.

## Worker configuration

The existing authenticated server configuration works without a worker. Start
the independent fake journal, then add its `ready.json` endpoint to that config:

```sh
python3 -B tools/fake_provider.py --directory target/fake-provider
```

```json
{"effects":{"endpoint":"http://127.0.0.1:12345","mode":"delivery"}}
```

This fragment augments the existing listen/identity/admission configuration.
Run the ordinary `serve` command. Only the compiled fake action and a loopback
HTTP origin are accepted. Inputs cannot select URLs, credentials or handlers.
Keep the provider's `journal.sqlite` across backend restarts: it records calls
separately from unique accepted actions. The harness's optional
`probe_directory` pauses named boundaries outside transactions for acceptance.

`mode` is explicit: `disabled` (the default) stops worker activity; `delivery`
permits submission, observation and application; `reconcile` permits provider
reads, inbox consumption and application only. A configured endpoint alone
does not enable delivery. Status and integrity expose `worker_mode`.

One server owns one worker, with two HTTP calls and five-second transport
deadlines. Persisted polling recovers missed wakes; each turn visits at most
sixteen rows. Ten-second leases permit two renewals and thirty seconds maximum
ownership. Every activation rotates a fresh local fence. Submission claim/start
recheck captured requester permissions and credential epoch. A provider-start
marker must commit before submission.

Timeout, lost response and expired started ownership require reconciliation.
Empty lookup is inconclusive. Only definitive nonacceptance of the current call
permits another submission within the original deadline and three-claim budget.
Read-only observations stop after six automatic attempts with persisted backoff.
Expiry/revocation cannot erase a fact from an already authorized action; local
leases cannot stop an in-progress remote call.

## Signed provider events

Add `ingress_secret_file` to `effects` to enable `POST /effects/fake`. It is an
absolute path to 32–128 raw secret bytes, loaded at startup. For example,
`openssl rand 32 > /absolute/private/webhook.secret` under `umask 077` creates
a disposable secret. The signer uses exactly those bytes, including any newline;
the secret and authorization headers are never stored with events. The endpoint
is unavailable without this configuration. Ingress can persist events while the
worker mode is `disabled`; consumption waits for an active mode.

Send `Content-Type: application/json` and exactly one of each header:

- `x-fake-account`: `fake-account-1`.
- `x-fake-event`: a canonical nonzero event UUID, stable across delivery retries.
- `x-fake-timestamp`: canonical integer Unix milliseconds, within five minutes
  of receipt. Retries may be signed with a fresh timestamp.
- `x-fake-signature`: lowercase hexadecimal HMAC-SHA-256.

The signed input is `account + "\n" + event + "\n" + timestamp + "\n" + raw_body`.
The body is `{"execution_id":"...","outcome":{...}}`, using the compiled
outcome shape from `model public`. The outcome must match the execution, action,
account and frozen units. Verification covers exact raw bytes before typed JSON
parsing. Duplicate object keys and unknown fields reject. The route enforces an
8 KiB raw-body limit and a separate two-second read deadline, with the server's
bounded admission held through the durable write.

HTTP 200 means the event is durably stored, with `duplicate` indicating an
identical retained event. It does not certify domain application. Same event ID
with different raw content returns 409; unknown executions return 404. Invalid
authentication returns 401, invalid payload 400, size overflow 413 and read
deadline 408. Admission returns 429; capacity/storage/unknown commit returns 503
without a positive ACK. Retry identical events after an uncertain response.

Inbox and due turns alternate, visiting at most sixteen rows per turn. Stable
inbox cursors advance past consumed or capacity-blocked rows and wrap, including
across activation. Consumption and the immutable provider fact commit together;
domain application follows independently. Older pending events cannot regress
success, erase a blocked diagnostic or repeat an applied result.

## Status, cancellation and retry

`effects.status {model, execution_id}` returns safe request/outcome, source,
target, revision, schedule, phase, application, budgets, diagnostic and provider
key to a current Account reader; unavailable rows return `null`. Remote phase
and application are separate: `succeeded` can be `pending`, `blocked` or `applied`.
Offline checks also report blocked/uncertain counts, expired leases and oldest
eligible age.

`effects.cancel {model, context, operation_id, execution_id, if_revision}`
requires current Account Update and requester or administrator authority.
Revision is a canonical integer string. Before start, cancellation clears the
lease and becomes terminal. After start/acceptance it invalidates ownership and
retains `uncertain` until reconciliation. Known terminal success/failure stays
terminal. Cancellation provides no compensation.

Save exact cancellation parameters, including the original `session.describe`
operation context, before sending. Replay and `operations.status` use that
context/operation ID. Record mutations/cancellations share one receipt namespace
and archive fence. Current target Read controls disclosure; a permitted command
may return `null`. Never refresh an archived uncertain operation's context.

Repair a blocked Account through the ordinary authenticated API, stop the server
gracefully, then retry using the current execution revision:

```sh
rebase-next --model effect-demo effects retry store.redb <execution-uuid> --if-revision <revision>
```

Restart the configured server to apply. This also permits another bounded
observation round for uncertain/waiting work, including a quarantined ready row
whose observation claims were exhausted by repeated ownership loss. It never resets submission attempts
or turns uncertainty into ready work. Offline `rpc` supports the same status
method for reading revision after shutdown. There is no public worker capability
or arbitrary patch API.

## Storage and boundaries

Limits: 64 unresolved /256 retained executions, 1,024 facts, 1 KiB requests,
2 KiB outcomes, 256 inbox events of up to 8 KiB raw JSON, 256 diagnostic bytes,
8 MiB accounted private bytes. Each
nonterminal execution reserves one fact slot and 4 KiB for its terminal result;
discretionary observations cannot spend another row's reserve. Applications use
the existing 200,000-unit engine budget, invariants and reader/index repair.
Duplicate facts consume no second slot. Contradictory terminal facts remain
conflict evidence and cannot overwrite applied success.

Integrity reconstructs fact links, due classes, counts and bytes and verifies
frozen bindings, application revisions and action/model identity. Backup contains
all private tables within the existing 64 MiB envelope. A pending inbox row also
reserves its consumption-marker bytes. Receipt archive preserves external
evidence. Reset requires a stopped worker and rejects unresolved work, unapplied
success facts or pending inbox events. Consumed retained events permit a clean
reset; there is no pruning or abandonment override at capacity.

Effect-bearing restores rotate activation, clear leases and quarantine unresolved
rows. Restored stores accept `reconcile` activation and refuse `delivery` and
new Dispatch creation until a clean reset. Account repair remains available.
They never infer nonexecution from an empty provider lookup, even when the
snapshot predates the provider-start marker. Stop the old writer before restoring
one replacement copy. Execution/provider keys survive restore; store/activation
identities change on clean reset, so old contexts and execution events cannot
attach to reused source IDs. No force-ready override, live-provider, distributed-clone or
exactly-once remote-execution claim is made.

Source 0.12 uses store format 9 /native codec 6 /effect codec 3 /API 3. The four
existing model identities are unchanged; older stores require matching binaries.
There is no implicit migration. See [storage](storage.md) for recovery procedures.
