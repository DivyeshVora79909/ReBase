# Bounded external work

Source 0.11 implements the experimental `effect-demo` worker against an independent
local fake provider. Business changes and immutable intent commit together.
Provider facts commit before a separate ordinary domain application. The
[G5b checkpoint](../research/38-fenced-worker-implementation.md) owns acceptance;
the last packaged deployment remains 0.6.0.

```sh
python3 -B tools/effects_worker.py --binary path/to/rebase-next --out target/effect-worker-run
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
{"effects":{"endpoint":"http://127.0.0.1:12345"}}
```

This fragment augments the existing listen/identity/admission configuration.
Run the ordinary `serve` command. Only the compiled fake action and a loopback
HTTP origin are accepted. Inputs cannot select URLs, credentials or handlers.
Keep the provider's `journal.sqlite` across backend restarts: it records calls
separately from unique accepted actions. The harness's optional
`probe_directory` pauses named boundaries outside transactions for acceptance.

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
observation round for uncertain/waiting work. It never resets submission attempts
or turns uncertainty into ready work. Offline `rpc` supports the same status
method for reading revision after shutdown. There is no public worker capability
or arbitrary patch API.

## Storage and boundaries

Limits: 64 unresolved /256 retained executions, 1,024 facts, 1 KiB requests,
2 KiB outcomes, 256 diagnostic bytes, 8 MiB accounted private bytes. Each
nonterminal execution reserves one fact slot and 4 KiB for its terminal result;
discretionary observations cannot spend another row's reserve. Applications use
the existing 200,000-unit engine budget, invariants and reader/index repair.
Duplicate facts consume no second slot. Contradictory terminal facts remain
conflict evidence and cannot overwrite applied success.

Integrity reconstructs fact links, due classes, counts and bytes and verifies
frozen bindings, application revisions and action/model identity. Backup contains
all private tables within the existing 64 MiB envelope. Inbox remains empty until
G5c. Receipt archive preserves external evidence. Reset requires a stopped worker
and rejects unresolved work or unapplied success facts.

Effect-bearing restores rotate activation, clear leases and quarantine unresolved
rows. **G5b refuses worker activation for restored stores.** G5c must prove
reconciliation from a backup predating remote acceptance before lifting this
restriction. No force-ready override, live-provider, distributed-clone or
exactly-once remote-execution claim is made.

Source 0.11 uses store format 8 /native codec 6 /effect codec 2 /API 2. The four
existing model identities are unchanged; older stores require matching binaries.
There is no implicit migration. See [storage](storage.md) for recovery procedures.
