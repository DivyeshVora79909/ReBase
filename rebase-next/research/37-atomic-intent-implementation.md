# G5a implementation choices

**G5a accepted after `73a9bc0`, 2026-10-23.**
The [executed evidence](evidence/2026-10-23-g5a-atomic-intent.json) records 24
affected Rust tests, eleven corrupt check/startup/restore controls and one
optimized authenticated HTTP workflow. G5b worker/provider execution is next.
The owning [external-work gate](33-external-effects-gate.md) and
[integration review](35-external-integration-review.md) remain in force.

Use the existing model-owned native `Input` as the frozen request for the first
Dispatch action. A small optional action declaration and pure template hook on
`Binding` identify its target and authored schedule. No erased request values,
provider registry, second engine or new associated type is needed. Prepare from
final staged records; never retain intermediate command fields as the request.
The engine supplies the creation clock and execution UUID after receipt replay.
The current redb mutation is not automatically retried; any future retry adapter
must capture those inputs once outside its retry closure.

Add checked execution/due storage and an effect-runtime header in the existing
transaction. Fact/inbox tables are present but must be empty in G5a; typed
provider facts and their writers enter G5b/G5c. G5a admits only ready and cancelled
execution states and their checked transitions. Future remote phases remain
unaccepted until their handlers and evidence exist. No restored dispatch can run:
G5a has dispatch disabled, and an effect-bearing restore also rotates activation
and records quarantine before publication.

Creation returns bounded execution references in the ordinary mutation result.
Status and receipt disclosure follow current target Account visibility.
Cancellation requires target Update and the original requester or administrator.
Record and cancellation receipts have an explicit kind under one actor/operation
namespace, count and archive fence. Current output receipts retain their public
record-result shape when they contain no effects.

A retained execution pins its Account even after Dispatch deletion. Account
deletion performs one bounded scan of at most 256 retained executions; ordinary
updates use point reads and new-intent writes. This avoids another maintained
reverse index for the small initial envelope. Due work uses its own exact ordered
index. All rows, counts and reservations are reconstructed independently during
complete checking. A fixed header allowance and reserved result bytes count
against the private 8 MiB bound.

Use source 0.10 /store 7 /native codec 6 /effect codec 1 /API 2. The new effect-demo
binding owns its behavior identity. Other model formulas and native bytes remain
unchanged; the new store layout deliberately rejects prior format-6 stores.
Preserve matching predecessor binaries and stores. No implicit migration.

Verification is one focused native effect suite plus the changed optimized HTTP
workflow and existing receipt/lifecycle controls. Cover actual writes followed
by abort, current authority, replay/content/archive fences, source reuse,
64 unresolved/256 retained limits, corrupt inventory and disabled restore.
Do not repeat unrelated numeric, tree or population campaigns. G5a proves durable
intent and cancellation; provider delivery/application remains G5b and durable
webhook ingestion/remote reconciliation after restore remains G5c.

## Executed result

The eight effect controls and sixteen existing local/authority/lifecycle tests
pass. Nine injected failures occur after actual domain/intent/due/runtime/receipt
writes across creation and cancellation and preserve all eleven application
tables. Native controls fill 64 unresolved and 256 retained executions, replay
at capacity, reject overflow without a receipt, restore the execution-boundary
fixture with a fresh disabled activation, retain evidence across archiving and
reject reset until cancellation. They also exercise current target authority,
source reuse, immutable fields, expiry, allocation collisions, exact due-key
ordering and action declaration validation.

Eleven corrupt images reject complete checking, network router construction and
restore without a published destination. They distinguish missing due rows,
request hashes, action versions, target bindings, byte counters, enabled dispatch,
unimplemented fact/inbox rows, receipt kind, phase/revision and missing receipt
execution references. Empty-effect stores retain their application bytes on
restore through the existing lifecycle controls.

The optimized real HTTP workflow passes seven record mutations /nine commands
(four commits and three complete rollbacks), one cancellation with replay, and
cross-method/content/stale-revision controls. It independently checks literal
balance 12 → 10 with frozen units 3, current target visibility, source reuse,
process kill/reopen, quarantine restore and receipt archive fencing. It performs
no provider action. Its execution took 1.732 seconds; the reused-cache optimized
binary build took 222.002 seconds. No full optimized Rust suite or old population
campaign was repeated.

`target/g5a-accepted/rebase-next` is the retained executable; its SHA-256 is
`b543aa119740e8c81ceea5cacefb172a9bf518567e0b508ef62aea28b52eb334`.
Source is 0.10.0, store 7, native codec 6, effect codec 1, API 2. Effect-demo's
model is `c05ccba953c9c8f0547bcfd9822cca79f54d9a86d6c14cb995f19d82c4fe51d7`.
The four prior model identities are unchanged. The matching 0.9 binary validates
the retained invoicing fixture; 0.10 rejects it with its physical file SHA-256
unchanged. No format migration or new deployment bundle is supplied.
