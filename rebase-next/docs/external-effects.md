# Atomic external-work intent

Source 0.10.0 adds the experimental `effect-demo` model. It commits immutable
external-work intent with ordinary business changes and their operation receipt.
G5a supports status and cancellation. Dispatch is durably disabled; no provider
call, worker, result application or webhook handling is accepted by this gate.
The last verified deployment bundle remains 0.6.0.

Run its authenticated workflow against a source-built executable:

```sh
python3 -B tools/effects.py --binary path/to/rebase-next --out target/effect-demo-run
```

The workflow creates Account balance 12, then atomically changes it to 10 and
creates Dispatch units 3. Balance remains 10. Future provider success and the
resulting balance 7 belong to G5b. The workflow also checks current permissions,
replay conflicts, complete rollback, source reuse, crash recovery and restore.

## Model and request

Select `--model effect-demo` before every executable command against this store.
The public catalog is the authoritative input declaration:

```sh
rebase-next --model effect-demo model public
rebase-next --model effect-demo fixture plan atomic-intent --namespace <uuid>
```

Account (101) has an authored `balance`, a canonical integer string bounded to
one million in magnitude, with a terminal rule requiring a nonnegative settled
value. Dispatch (205) has immutable `account`, positive `units` up to one million,
`execute_at` and `not_after`. All four fields are required; the two schedule
fields accept a canonical millisecond string or `null` for their defaults.

Create a Dispatch through `records.mutate`. It requires ordinary Create and
reference Read permissions plus current Update authority on its Account.
There is no separate enqueue call. The model freezes the final Dispatch input,
target Account, requester and credential epoch, action version and fixed
`fake-account-1` provider configuration. Generated execution UUID and clock values
are allocated only after receipt replay and successful domain settlement.
The redb writer does not automatically retry transactions.

Default due time is creation time and default expiry is sixty seconds later.
Explicit due time fits within twenty-four hours before or after creation;
expiry must be later than creation and due time, and at most twenty-four hours
after creation. Times are trusted wall-clock milliseconds, separate from model
business time. Expiry will govern submission in G5b; G5a does not run a poller.

A committed result includes `executions`, with `execution_id`, `source` and
`target` for each new intent. The field is omitted when empty or when current
target visibility hides every execution. Deleting Dispatch does not delete its
execution. Reusing the source UUID creates a new execution and provider key;
replaying the original operation does not. Every retained execution pins its
Account, including after cancellation or source deletion.

## Status and cancellation

`effects.status {model, execution_id}` returns the safe frozen request, source,
target, revision, schedule, phase, cancellation and stable provider key to a
current Account reader. It returns `null` when unavailable. Only this compiled
model advertises these methods; other models keep their existing method set.

`effects.cancel {model, context, operation_id, execution_id, if_revision}`
requires current Account Update authority and either the original requester or
an administrator. Revision is a canonical integer string. In G5a a ready
execution at revision `"1"` becomes cancelled at `"2"`. No provider work is
possible, so this gate does not imply safe cancellation of a started remote call.

Retain the exact cancellation parameters in a private JSON file, including the
original `session.describe` operation context, before calling the method through
`tools/client.py call effects.cancel <params.json>`. Reuse those parameters to
retry. Query `operations.status` with the same model/context/operation ID to
reconcile. Record mutations and cancellations share one actor/operation
namespace, receipt count and archive fence; different content or a different
method conflicts. Never refresh an old operation's context after archiving.
Cancellation responses and stored receipt disclosure use current target Read
permission, so an authorized cancellation can return a `null` result.

## Storage and bounds

The store permits 64 unresolved and 256 retained executions, 1 KiB per frozen
request and 8 MiB of accounted private bytes. Each unresolved execution reserves
one future fact slot and 4 KiB of result capacity. A fixed 4 KiB header allowance
is also charged. Duplicate receipt replay does not allocate or charge capacity.
The model permits 64 Accounts /256 Dispatch sources, 320 total, with no private
calculation outputs. These are enforced prototype bounds.

Five private tables hold executions, exact ordered due keys, facts, inbox and
runtime. Facts/inbox must remain empty in G5a. Complete integrity independently
reconstructs due rows, counts and reservations and checks request hashes,
action/model versions, target references and receipt links. They share the
ordinary atomic writer, complete observation and 64 MiB backup envelope.

Receipt archiving preserves all effect evidence. Reset rejects unresolved work;
after cancellation it can clear retained evidence only as part of the explicit
whole-store reset. Restore validates the supplied image, rotates activation and
quarantines effect-bearing stores before publishing a new destination. Dispatch
remains disabled. Empty-effect restores preserve application-table bytes.
Provider reconciliation from a backup predating remote execution remains G5c.

Source 0.10 uses store format 7, native codec 6, effect codec 1 and API 2. The
four existing model identities are unchanged, but their old format-6 stores
intentionally reject. Preserve matching binaries/backups; there is no implicit
migration. The [storage guide](storage.md) owns general recovery procedures.
