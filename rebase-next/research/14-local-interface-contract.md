# Local model, API and demonstration contract

**P2–P4 implementation contract, 2026-10-22.** This narrows paper 7 to the
confirmed usable local prototype. It does not add a general model interpreter,
production identity service or an HTTP deployment requirement.

Implemented and accepted in [paper 16](16-local-prototype-result.md).
The [run/API guide](../docs/local-prototype.md) supplies concrete commands and
request examples. Older illustrative shapes in paper 7 remain proposals.

## Prepared model and tools

One bundled model combines authored Draft 2020-12 input schemas, explicit stable
contract/field/slot codes and ordinary trusted Rust behavior. Preparation checks
schema closure, code uniqueness, typed reference targets, compatible root/member
and query declarations, public fields and the declared local calculation order.
Schemas are self-contained; references and network resolution are rejected, and
annotation defaults are never installed.
Exact string binding, reference existence and global rules remain engine checks.
Only this compiled model is supported; loading arbitrary behavior is not claimed.

Offline commands export a public contract or a separate developer catalog and
explain a selected contract. The public projection contains input schemas,
permitted operations, exact bindings and published fields/roots. The developer
projection additionally contains private roles, formulas, dependencies and source
locations. Export writes to stdout, so preparation never opens a database, prunes
a directory or overwrites source files. Presentation assets do not identify the
model. The semantic fingerprint includes prepared declarations/schemas and the
compiled core's source fingerprint, covering behavior bodies and the codec.

## Local storage and entrypoint

One binary provides `model`, `init`, `rpc`, `inspect` and `demo` commands.
`rpc` serves one JSON-RPC 2.0 request per stdin line and one response per stdout
line. This is a directly usable local process API; HTTP transport remains an
adapter choice. Reject batches and notifications, including mutation requests
without a response ID. Request IDs are bounded strings. Limit input bytes before
JSON decoding and reject duplicate JSON object keys.

`init` creates a new store only, with explicit tenant/actor UUIDs; it refuses an
existing path. Opening an existing store never initializes or reinterprets it.
The process acts as the store's fixed local actor. Every operation verifies the
model, codec and bound context against the same transaction snapshot. Client
params cannot select another actor, private fixture mode or storage namespace.
This is a local process trust boundary, not login/authentication.

The reusable redb adapter owns native KV, a complete public-record ID index,
operation receipts and its private format/header. The public index is updated
from final record changes in the same transaction as all engine state. It is
complete for the fixed actor/tenant; a general reader DAG needs a different gate.
No public operation directly edits that index, tree state, roles or receipts.

## Requests and outcomes

All operation params require the exact model identity except `model.describe`.
Unknown fields reject. Domain integers, versions and times retain canonical
decimal strings; codes, limits and bounded counts are JSON integers.

| Method | Params and result |
| --- | --- |
| `model.describe` | Empty params; public catalog only. |
| `records.get` | `model`, canonical `id`; permitted record envelope or `null`. Private/absent identities share `null`. |
| `records.mutate` | `model`, `operation_id`, `commands`, `returning` UUID list. Core create/update/delete rules apply. Return confirmed revision, operation identity and settled permitted record envelopes/nulls only after commit. |
| `operations.status` | `model`, `operation_id`; `committed` receipt or `not_observed`. Absence does not prove an operation never ran. |
| `records.page` | `model`, declared `query`, `limit`, `visit_budget`, nullable `cursor`; ordered public records, visited count, exhausted flag and continuation. |
| `records.exists` | Same query/cursor/visit budget; `yes`, `no` or `unknown` and continuation when needed. |
| `roots.read` | `model`, owner UUID, root slot and declared read (`summary`, `before` timestamp or `latest` timestamp). Published values/revision only; no private occurrence identities. |

The record envelope contains `id`, contract code, exact version, `input` and
published `derived`. Mutations accept 1–64 unique source IDs; returning accepts
at most 32 unique public IDs. Protected output/Pin contracts always reject.
Public errors have stable kinds and safe messages; native causes stay in trusted
diagnostics. No external operation delivery or background effects are present.

Receipts bind the normalized request to the local model, tenant and actor.
Same operation ID/same content replays the confirmed result without advancing
revision; different content rejects. Data, public index and receipt commit
atomically under redb's serialized writer. Rejections leave all tables unchanged.
A commit I/O error is `outcome_unknown`; a client retains its operation ID and
reconciles after reopening. Receipts have a declared lifetime limit of 1024 and
are not evicted; reaching it rejects further new mutations. This is a bounded
local replay policy, not unlimited retention or distributed exactly-once claims.

## Bounded reads and cursors

The registered path is `records.by_id`, ascending UUID byte order. The query
optionally selects one public contract and one exact equality predicate on a
declared scalar authored field of that contract. No arbitrary ordering, private fields,
expressions or implicit indexes. Whole records are the initial projection.
Every candidate, including a residual-filter reject, consumes a visit. Result
limit is 1–32 and visit budget 1–128. An empty filtered page may have continuation.
`exists=no` requires exhausted remaining scope; a budget without a match is
`unknown`. A match is enough for `yes`.

Cursors bind store identity, model, fixed actor/tenant, canonical query, last
visited public UUID and the store's global mutation revision. Authenticate them
using HMAC-SHA256 and a per-store private key. Changing query/scope/token rejects;
any intervening committed mutation returns `query_changed`, including no-op
mutations and field-only edits. A receipt replay does not change revision.
Limit/budget may change on resumption. Reauthorize and use one new read snapshot
per page. The coarse revision deliberately favors simple correct local behavior;
there is no frozen multi-request snapshot/export promise. Cursors survive reopen
while their revision remains current.

Root publications remain distinct from record-list filtering. Account history
supports summary and strict `before`; subsidiary history supports summary;
curve quotes support summary and `latest`. Equal-time strict prefix excludes
every occurrence at that time, including at i64 extremes. Aggregate reads may
include private contributions as explicitly published by the owner contract;
they do not expose the contributors' private records or role IDs.

## Demo, inspection and acceptance

The named disposable demo creates a new directory/store and uses the same public
operations to seed the causal/diamond fixture, edit dates/targets, show before
and after values, demonstrate stale-version and feedback rejection, replay a
receipt, and reopen. The trusted `inspect` command gives a bounded developer
view including actual private roles; it is separate from the public RPC methods.
No native-node fixture or alternate calculation implementation drives the demo.

Verify model preparation/export and meaningful invalid declarations; public
schema/binder agreement; strict ingress and private-state protection; receipt
atomicity/replay/content conflicts; bounded empty-page/exists behavior; cursor
query/store/tamper/revision/reopen semantics; and final raw state against the
independent source oracle. Include raw tables and index/receipt inventories in
the local acceptance evidence. Keep earlier P1 and research evidence dated.
Run affected checks while developing and the integrated locked checks at closure.
