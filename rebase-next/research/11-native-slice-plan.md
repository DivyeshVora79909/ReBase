# First native mutation slice: implementation plan

**Status: implemented and accepted through S1–S5, 2026-10-22.**
[Paper 12](12-native-slice.md) owns the execution results;
[paper 8](08-research-workflow.md) owns the remaining gates. This plan made the
M1/M2/M4 fixture implementable after the [M3/M5](09-causal-settlement.md) and
[M6](10-independent-checker.md) contract work. Its original
[planning evidence](evidence/2026-10-22-native-slice-plan.json) remains unchanged.
The later user request authorized autonomous completion of the stages below.

## 1. Question, boundary and existing pieces

Can one native attempt apply bounded authored changes, maintain their declared
consequences in linked indexes, reject an invalid complete-time history and
atomically persist exactly the accepted state? The independent answer comes
from intended commands and source arithmetic, not from the maintained indexes.

Success requires complete inventories and valid actual structures as well as
correct amounts. An unchanged sum cannot excuse a lost dependency. Any failure
to establish those properties stops the slice; do not widen the application to
work around it. This is an embedded research implementation, not acceptance of
the proposed public `records.mutate` API.

| Inspected existing piece | Reuse and missing work |
| --- | --- |
| [`algebra.rs`](../src/algebra.rs) | Reuse checked `i128` financial summaries and complete-time boundaries. It caches first/last **times**, not full occurrence keys. It has no tree writer. |
| [`plan.rs`](../src/plan.rs) | Reuse explicit local dependency ordering. It does not discover cross-record consumers. |
| [`staging.rs`](../src/staging.rs) | Reuse point-overlay semantics and final `Batch`. The current byte overlay does not supply a typed node workspace or staged ranges. |
| [`feasibility.rs`](../examples/feasibility.rs) | Reuse the redb transaction/abort/reopen pattern. Its one-leaf nodes and system-temporary directory are not the new fixture layout or output location. |
| [`m6.py`](experiments/m6.py) | Reuse independent inventory/tree-walk obligations. Its IDs, financial cache shape and M3/M5 oracle are fixture-specific; it cannot check native bytes unchanged. |

Use one Cargo package, ordinary modules and the existing pins. No range overlay
is needed here: domain traversal follows staged point-addressed tree links;
reverse routes are bounded point-addressed lists. A full raw scan belongs to
the privileged test observer, not mutation discovery.

## 2. Fixed model and exact values

There is one tenant and a verified toy actor supplied by the local harness.
Records have server-assigned tenant, owner and reader; owner and reader equal
that actor throughout this fixture. Ordinary writes and new authored references
require that same actor/tenant. Another actor, cross-tenant reference or forged
context field rejects. This exercises a narrow boundary, not principal-DAG,
sharing, credential verification or revocation behavior.

| Code / record | Required authored fields | Mutable fields | Maintained role |
| --- | --- | --- | --- |
| 1 / Rule | `c` | `c` | Direct coefficient source; no ordered root |
| 2 / Curve | `native_unit`, `reporting_unit` | None | Quote root |
| 3 / Quote | `curve`, `at`, `rate` | All three | One quote membership |
| 4 / Account | `native_unit` | None | Native history root with nonnegative complete-time balance |
| 5 / Subsidiary | `reporting_unit` | None | Reporting history root |
| 6 / Posting | `units`, `at`, `rule`, `curve`, `account`, `subsidiary` | All six | Two calculated values, two required memberships and one quote query |

Reference targets have exactly the types in this table. A posting's account
unit equals its curve's native unit; its subsidiary unit equals the curve's
reporting unit. Unit codes are explicit nonzero `u16` labels, not inferred from
UUIDs. Rule `c` is dimensionless. Unit fields are immutable; changing the model
or converting units is outside this fixture. No authored field is optional or
nullable and there are no implicit defaults.

Native values are UUID bytes `[u8; 16]`, signed `i64` nanoseconds, signed `i128`
units/amounts, `u16` coefficients/rates and checked `u64` revisions. Heights and
authored counts use `u16`; summary counts retain the proof's `u64` type.
Require `-1000 <= units <= 1000` and `1 <= c, rate <= 1000` before arithmetic;
check signed bounds without taking the absolute value of an unbounded input. Each
reporting contribution is at most `10^9` in absolute value. At most 16 postings
bound the sum of absolute contributions by `16 * 10^9`, including intermediate
regroupings. Use checked multiplication/addition despite those bounds.

Support the full `i64` timestamp range. Time comparisons never add a nanosecond
or substitute a maximum UUID. All domain integers, times, amounts and revisions
in fixture JSON and persisted values use canonical decimal strings: `0`, or an
optional minus followed by a nonzero digit and remaining digits. Reject `-0`,
leading zeros, plus signs, exponents, whitespace, floats and booleans. Unsigned
fields additionally reject a minus. UUID strings must round-trip to canonical
lowercase hyphenated form. Small schema/slot/unit codes and bounded counts may
be JSON integers. No value passes through a JavaScript number.

The final state has at most **64 authored records, 16 quotes and 16 postings**;
one operation has 1–64 commands with distinct source UUIDs. Enforce final-state
counts before tree work; temporary old/new images are allowed within that
bounded attempt. Old/new posting populations together contain at most 32 IDs.
These are research resource limits, not production capacity claims.

### Codes and reproducible identities

Codes are explicit and unique within their typed namespace. Root slots are
`quotes=1`, `native_history=2`, `reporting_history=3`; member slots are
`native=1`, `reporting=2`, `quote=3`; query slot `rate=1`.
Authored field codes follow the table's written field order, starting at 1
within each record type. Posting derived codes are `native_minor=7` and
`reporting_minor=8`. Input field codes and calculated field codes share that
posting field namespace. Never allocate codes from alphabetical order.

The baseline uses these fixed UUIDs, all with prefix
`00000000-0000-4000-8000-` and the twelve-digit suffix below:

| Label | Suffix | Role |
| --- | --- | --- |
| T, U | `000000000001`, `000000000002` | Harness tenant/actor, not authored domain records |
| D | `000000000010` | `c=2` |
| C | `000000000020` | Native unit 1, reporting unit 2 |
| A, B | `000000000030`, `000000000031` | Native accounts, unit 1; B starts empty |
| S | `000000000040` | Reporting subsidiary, unit 2 |
| X, Y | `000000000050`, `000000000051` | Quotes `(10,3)`, `(20,5)` in C |
| P, Q | `000000000060`, `000000000061` | Postings `(at=15, units=4)`, `(at=25, units=1)`, both D/C/A/S |

Additional case IDs must be fixed and distinct in the fixture file. Initialize
an empty bound store at revision 0, then create the baseline in one operation,
with referenced records earlier in the command list. Its record/root revisions
are 1. UUID allocation and managed-output reservations are not exercised.

## 3. Commands, versions and lifecycle

The local harness binds JSON into three typed commands, with unknown fields
rejected:

| Command | Meaning |
| --- | --- |
| `Create {id, contract, fields}` | Complete authored input; create only if the record UUID is absent at this command's staged point. Install its required empty roots/routes too. |
| `Update {id, if_version, set, unset}` | Change only allowed authored fields; omission leaves them unchanged. Validate the full resulting input. All fields here are required, so any nonempty `unset` rejects. An empty `set` is a permitted no-op. |
| `Delete {id, if_version}` | Remove this source and its own roles subject to final REJECT-reference checks. No implicit cascade or bulk-delete shortcut. |

One command per UUID excludes create/update or delete/recreate of that UUID
inside an operation. Updates/deletes compare the supplied equality version with
the attempt's original record version. They cannot overwrite another command's
source edit or address derived values, links, revisions, authority or receipts.

Each created/updated input's references must resolve in the staged command view:
earlier creations are available; forward references and already staged deletions
are unavailable. Deleting a parent can precede deleting/reparenting its existing
children: keep old images, and decide whether a reference **survives** only at
final validation. A new link to a parent already marked deleted still rejects.
Selected quotes are query results, not authored REJECT references; deleting one
reselects or falls back. Deleting a referenced curve/rule/account/subsidiary
without removing all final inbound references rejects.

Quote-time uniqueness is a final-state rule within each curve. Swapping X/Y's
times in one operation is valid; two final quotes at the same time are not.
Remove all old quote occurrences whose positions change before inserting their
final positions; an unchanged-position rate edit can revalue its existing node.
Do not reject a temporary collision or historical deficit while the operation
is incomplete.

Use a checked store commit counter. Each accepted operation, including a semantic
no-op, increments it once; a rejection increments nothing. A created record's
version is that counter. A surviving record receives the new version exactly
when its authored/header or own calculated-field values change. A deleted UUID
may be created in a later operation only after all its references/roles are gone;
the store counter gives that new lifetime a distinct version, avoiding stale
editor equality after reuse. Counter exhaustion rejects before commit.

Root content revisions are separate. Advance one when the logical ordered
population, key or leaf payload changes, including a quote-rate edit or
offsetting amounts that preserve the total. A rotation alone advances neither
root content revision nor source record version. Compare each changed member's
original and final root/key/payload; temporary removal/reinsertion is not itself
a content change. Root publications are returned with their root revision;
they are not implicitly part of an owner's record
version. Query provenance is private here: changing the selected quote at an
equal rate changes its descriptor, while unchanged posting amounts alone do
not change that posting's version. Future public projections must retain this
explicit distinction.

## 4. Physical state and attempt ownership

Use one redb application table `native_kv`, with these exact point-key forms.
UUIDs are 16 bytes and codes are two-byte big-endian integers. The namespace
tag has one byte; keys have no optional trailing bytes or business-time encoding.
Reject unknown tags, wrong lengths, codes or key/value identity disagreements.

| Tag / key after tag | Stored value and obligation |
| --- | --- |
| `00` / empty | Model/codec identity, fixed tenant/actor, commit counter, six authored counts |
| `01` / UUID | Contract/header, authored payload, own derived values and record version |
| `02` / owner UUID + root slot | Root kind, head/first/last member IDs, height, publication summary, content revision; include empty roots |
| `03` / source UUID + member slot | Root ID, full key, leaf payload, parent/left/right/prev/next member IDs, height and subtree summary |
| `04` / posting UUID + query slot | Exact query descriptor, selected quote UUID or absence, and rate result |
| `05` / target UUID | Sorted incoming authored-reference list `(consumer UUID, field code)`; present for every live authored record, even empty |
| `06` / rule UUID | Sorted direct-user list `(posting UUID, native_minor field code)`; present for every rule |
| `07` / curve UUID + quotes root slot | Sorted subscriber list `(posting UUID, rate query slot)`; present for every curve |

Only account/subsidiary/curve records own roots in this model. Lists contain no
duplicates and retain role identity. They are point-owned bounded vectors, not
AVL interval nodes or a general reverse-index abstraction. Derive their expected
contents separately from facts. An absent required header is corruption, not an
empty list. Removing a source removes its now-unused headers and all its roles.

Every node has full key `(at, source UUID bytes, member slot)`, lexicographically
ordered with signed time comparison. Root-node parent is absent, leaf height is
1 and empty height is 0. Neighbours are reciprocal within the same root.
Financial nodes cache the existing `Summary`; quote nodes cache only count and
first/last times. Quote rate is a leaf payload, not a summed amount. Root headers
copy the corresponding summary and retain full endpoint member IDs. Full key
order and endpoint identities are independently checked even though summary
first/last fields are times. Do not fabricate extra cached full-key fields when
adapting M6's synthetic format.

Use deterministic Serde structs/enums and canonical scalar encoders for values.
The point keys need no ordered KV codec. The snapshot observer also retains raw
key/value bytes; normalized JSON is an explanation of them, not a replacement
for byte equality in rollback checks.

One attempt owns original bytes/decoded old images and one latest typed value
per touched key. Load/decode on first use; later reads and field patches use that
same latest object. Retain tombstones and old images until the attempt ends.
Encode dirty final values once, compare with original bytes and produce `Batch`.
Extend the point-workspace code only to provide this ownership; do not create
independently mutable byte and typed caches that can restore stale node fields.
Tree traversal, reverse-list edits and final publication use the same workspace.

### Binding the disposable store

Codec ID is `native-slice-kv-1`. Bind the model using SHA-256 over a fixed ordered
list of component names and exact bytes: the fixed model/command/permission/code
declarations, scalar/key codec, trusted calculation/settlement/tree/algebra/order/
staging sources, Cargo manifest/lock and toolchain file. Embed those bytes from
the compiled inputs so an old binary cannot supply a freshly computed identity
for code it does not contain. The implemented stage records the exact file list.
Names are relative to this directory and sorted by UTF-8 bytes, so moving the
directory or changing filesystem enumeration order does not change the digest.

Use domain prefix `rebase-native-slice-model-v1` plus a zero byte, followed by
each UTF-8 name and content, each preceded by its unsigned 64-bit big-endian byte
length. Use a maintained SHA-256 library with a pinned dependency, not a custom
hash implementation. This conservative identity may change on a source-only
refactor; that is acceptable for disposable stores. It is not the eventual
semantic-equivalence/canonical-model scheme. Documentation and fixture results
are excluded. Same-model reopen succeeds; any initialized-store mismatch rejects.
Read/check the header inside every write transaction. There is no in-place model
activation, migration or process-supplied override in this slice.

## 5. Dependencies and settlement

The posting calculations are exactly
`native_minor = units * rule.c` and
`reporting_minor = native_minor * quote_rate`. Its quote query is
`latest` on `(curve, quotes)`, phase `calculate`, channel `rate`, range
`[negative_infinity, after_time(at))`, fallback 1. `after_time(t)` is after every
full key at t, including at `i64::MAX`; it is not `t+1`. If an existing curve
has no quote at or before the posting time, selection is absent and the rate
is 1. A missing curve rejects.

The prepared calculation names deliberately oppose dependency order:
`a_reporting` consumes `z_native`, and those map to field codes 8 and 7.
Declare the consumer first too. The prepared order must still evaluate native
before reporting. Inputs are resolved values, not arbitrary database-reading
closures. Unknown inputs, duplicate names/codes and cycles fail preparation.

| Trigger | Candidate population |
| --- | --- |
| Create/edit/move/reparent/delete a posting | That posting, with its old and final source/slot images |
| Change/delete a rule | Union of its original and final direct-user lists |
| Create/edit/move/reparent/delete a quote | For both its old and new curve, union of original and final subscriber lists |
| Delete a root owner | Final inbound-reference list must be empty; remove empty owned roots after role reconciliation |

This intentionally reevaluates all subscribers of a changed curve, up to 16 per
state. Minimal changed quote intervals are not needed for correctness in this
slice. Tests still compare exact selected sources and old/new bounds. Keep every
posting's direct route, query and curve subscription, including zero units,
fallback selections and equal-rate replacements. A dependency is not merely a
link to the quote that previously answered it. Do not claim interval pruning
or distributed phantom protection from these lists.

The attempt performs this fixed sequence:

1. Check model/context, command uniqueness, shape and versions; stage authored
   commands in their declared order. Capture original images before edits.
2. Install required empty root/route headers for new sources and reconcile
   changed authored-reference, direct-user and subscriber lists. Keep original
   lists too; form the candidate union before retiring deleted headers.
   Check final counts, target existence/types/units and surviving REJECT links.
3. Remove deleted/moved old quote slots before inserting final new positions;
   revalue retained slots for rate-only changes. Enforce final unique times and
   finish their roots. All subsequent quote reads see that final tree, including
   inserts and deletions in this same attempt.
4. For each surviving candidate posting, bind final rule/query inputs and execute
   the prepared local order once. Replace its query descriptor and calculate both
   desired memberships. Deleted postings instead remove all their old roles.
5. Reconcile the native/reporting slots. Unchanged root/key/value needs no tree
   edit; a value-only change refreshes its ancestor summaries; a move removes the
   old occurrence and inserts the new one. Repair links/rotations only through
   latest workspace objects. Remove retired empty roots/route headers last.
6. After all candidates settle, validate every affected surviving account's
   complete-time minimum, including the empty prefix. Finalize logical content
   revisions, record versions and counts. No pending candidate may remain.
7. Form the result from settled state, encode/apply the final batch inside the
   same redb write transaction, commit, then release confirmed success.

No calculation consumes account/subsidiary history here, so their old private
contributions need not be detached merely to evaluate another posting. That
restriction makes this order sufficient. M3/M5's output detachment and interval
readiness remain required when prefix consumers are later added; this sequence
must not be generalized to them.

The incremental attempt starts from a valid committed store; the independent
observer checks that precondition in this bounded harness. Tree helpers expose
ordinary insert/remove/revalue/latest operations. They must
reject encountered broken links or impossible cached structure, not repair the
whole store. Each mutation has an explicitly supplied work budget, with no
unlimited default. Count command visits, reverse-list entries inspected, node
visits, first key loads and staged patches as separate counters and one summed
work counter. The fixture sets a generous recorded ceiling; a deliberately low
ceiling tests rejection. It is a resource guard, not a timing/performance target.

## 6. Independent expectations and real observation

Implement a small Python source oracle over the fixed authored fixture and its
intended command history. It independently decides input/reference/version
acceptance, selects quotes by scanning facts, computes native then reporting,
sorts full keys and groups equal timestamps. It spells out required roles and
reverse routes without calling Rust model preparation, discovery, tree code or
summary combination. Accepted operations advance its expected history; rejected
operations leave it unchanged. An unexpected runtime rejection is a failure,
not permission to remove the intended operation from that history.

Compare full record payloads/versions, root populations/revisions, members,
queries including selection identity/fallback, all three reverse-list kinds,
counts and metadata. The baseline has **9 authored records, 4 roots (including
empty B), 6 nodes, 2 queries, 10 authored-reference entries, 2 direct users and
2 curve subscribers**. There are 9 incoming-list headers, 1 direct-list header
and 1 subscriber-list header: with metadata, exactly **33 application KV rows**.
These are hand-derived planning expectations, not executed native results.

The observer exports every raw row from the complete application table in one
redb read snapshot and rejects an unexpected application-table inventory.
Preserve raw rows until duplicate decoded identity, malformed key/value and
namespace checks pass. Do not enumerate through roots, routes or a runtime
record registry; their disappearance is one of the failures being tested.
Unknown fields and unsupported namespaces fail rather than being filtered out.

Then apply M6's actual-link walk, full order/parent/neighbour/AVL checks, global
reachability and independent scans for every subtree and publication. The native
scan compares the **actual declared** time-based `Summary` fields, with optional
internal boundaries remaining absent where appropriate. It separately verifies
complete-time invariant results and full-key endpoints. Quote scans check their
smaller summary and authored rate payloads. No cached child summary supplies an
expected parent result.

Reuse only the fixture-independent checking mechanics when the second caller
exists. Keep M6's current source-oracle wrapper and financial/interval controls;
add a native expectation/observation adapter with explicit layouts and scan
functions. Do not synthesize missing native cache fields to make the old image
schema fit. If shared checker code changes, rerun M6 once and preserve its old
dated evidence. The unchanged M3/M5 order campaign needs no rerun.

Completeness is asserted by the harness after the scan reaches its end within
one held snapshot; no stored `complete` field certifies it. A partial export,
lost snapshot or exhausted checker budget is **incomplete**. Malformed complete
state is **invalid**. A synthetic accepted image cannot substitute for the raw
export of a state produced by native mutation.

## 7. Acceptance cases and rejection evidence

Each row is a focused group; use fixed cases and literal checks, not a broad
random campaign. Unless stated otherwise, start from the baseline. Paper 8's
[original arithmetic table](08-research-workflow.md#hand-worked-expectations)
remains authoritative; the added cases make implementation mistakes observable.

| Group | Required observations |
| --- | --- |
| M1 / coefficients and order | Baseline P=8/24, Q=2/10, A=10, S=34. Set c=3: P=12/36, Q=3/15, A=15, S=51. Opposed names/declaration order still work; malformed dependency declarations fail preparation. |
| M2 / quote selection | X rate 4 gives S=42. Insert a quote `(12,4)` gives S=42. Delete X or move it to 30 gives P=8/8, Q=2/10, S=18. Delete both quotes gives fallback P=8/8, Q=2/2, S=10; C and its subscriptions remain. |
| M2 / equal answers and bounds | Insert `(12,3)`: financial values stay at baseline but P selects the new quote. Move P to 25: P=8/40, Q=2/10, S=50; the two coincident query bounds retain distinct identities. Include latest at the exact quote time and both `i64` endpoints. |
| M2 / structural lifecycle | Edit units, delete P, reparent P to B, change its curve to an earlier-created empty curve, and move a quote between curves. Both old/new roots and routes must match source expectations; no disconnected old slot remains. Missing/wrong-type/unit/tenant targets reject. |
| M2 / uniqueness and final shape | Swap X/Y times together: P=8/40, Q=2/6, S=46. Final duplicate quote times reject. Delete an owner alone rejects; deleting/reparenting all inbound sources in the same operation permits its removal. Forward-created references reject. |
| M2 / zero and stale versions | Set P units=0: retain its two members and all routes. Change c and quotes, then restore nonzero units and check the new source values. Equal semantic state keeps its record version; relevant root revisions still change. Stale update/delete and delete/recreate with an old version reject. |
| M4 / settled histories | With c=1 and empty-curve fallback, `+10 @0, -15 @10, +10 @20` rejects despite final 5. `-10,+10` at the same time in one operation accepts with minimum 0 even when the negative UUID sorts first. |
| M4 / explicit checkpoints | Submit the negative leg as its own operation: it rejects and leaves empty history. Submit both legs in one operation: it accepts. Separate operations have separate commit/validation boundaries; there is no inferred checkpoint flag or cross-operation rollback. |
| Native writer structure | Short insertion orders force LL/RR/LR/RL rotations; deletion covers leaf, one-child, two-child, root and last node, including repair after a move. Check actual trees after every **settled operation**, with duplicate financial timestamps and two valid shapes. No prescribed final median node. |
| Native observation controls | Erase a whole subscriber list, remove an empty root or zero member, corrupt a direct/reference route, keep an old selected quote at an equal rate, corrupt a time cache/endpoint/link, duplicate a decoded identity or introduce an unknown raw key. Expect its named obligation, plus valid alternate-shape and incomplete-scope controls. |
| Embedded storage | Hold an old read snapshot across a commit; inspect a fresh snapshot; close/reopen the same model; reject another model/codec. Inject an abort after part of a dirty batch and again after the full batch before commit. |

For **every expected rejection**, capture the complete before/after application
KV key/byte map in fresh consistent reads and require exact equality, including
metadata/counter/counts, versions, empty headers, reverse lists, queries, node
links/caches and root revisions. Compare application KV contents, not physical
database-file bytes, which may change for storage-internal reasons.

At least one late invariant failure and one work-limit failure must occur after
in-memory changes. Test-only write-failure hooks also abort after actual redb
inserts/deletes, so overlay discard alone cannot masquerade as storage rollback.
No partial success/result escapes. A precommit injected abort has a known result;
an actual uncertain commit error stays unknown and must not be labelled rejected
or automatically retried.

There are **no durable operation receipts, effect intents, distributed guards or
automatic retries** in this harness. Complete namespace checking requires their
absence. This bounds the rollback claim to all state actually implemented; it
does not satisfy W1/T1–T3. The commit counter is a local revision, not evidence
of portable conflict protection.

## 8. Small implementation stages

These dependent stages were executed sequentially. S1's separate evidence
preceded native work; the user's subsequent autonomous-completion instruction
carried the bounded goal through S5. [Paper 12](12-native-slice.md) records the
results without relabelling old proof runs. Do not add empty future modules.

| Stage | Concrete output | Required check and stop boundary |
| --- | --- | --- |
| S1 — expectations and observation format | Add `research/fixtures/native-slice.json` and `research/experiments/native_slice.py`: exact authored cases/IDs, independent command/source oracle, explicit raw observation schema and corruption controls. Share only established checker mechanics where a second caller requires them. | Confirm the literal arithmetic/inventories/version changes above and valid/invalid/incomplete controls before native work. If M6 helpers change, rerun that affected checker. S1's synthetic format controls alone are not real snapshot acceptance. |
| S2 — native values and one point workspace | Add fixed native model/command/value/codec code in ordinary modules, prepare the adversarial local order, enforce limits, and bind model identity. Extend typed staging with one current value per key. | Exact scalar/UUID/key round trips, protected/unknown inputs, staged references/tombstones, version rules, mismatched identity and bounded-work rejection. Reuse the existing local-order checks; no generic model loader or RPC. |
| S3 — linked trees | Add `src/tree.rs` for this typed full key, financial/quote summaries, insert/remove/revalue/latest and complete-time validation inputs. | Small rotation/deletion/tie/extreme-time cases against the independent scans. Export actual node images, including empty roots. Stop on any inventory/link/cache mismatch; no whole-tree rebuild as repair. |
| S4 — connect M1/M2/M4 settlement | Connect the fixed source/route/quote/posting sequence to that workspace and writer. | Run the command groups with complete exported observations and rejection snapshots. Verify that staged quote edits affect postings in the same operation and old/new reparent routes disappear/install correctly. No prefix consumers or managed outputs. |
| S5 — redb acceptance and closure | Add a disposable native example/harness using the same settlement entrypoint, batch writer and full raw-table observer. Record actual counts and hashes. | Atomic old/new snapshots, all-key abort checks after actual writes, same-model reopen and model/codec rejection. Run the integrated locked Rust checks once; record precisely what passed. Stop at embedded native-slice acceptance. |

Keep model, command binding and fixed settlement together initially (for example
`src/native_slice.rs`); separate `tree.rs` and a small codec file when introduced.
The redb harness can remain an example/integration-test adapter using the existing
dev dependency. Promote the pinned UUID library to a normal dependency only when
core binding needs it; pin the standard hash dependency when introduced. There
was no dependency update in the original planning packet; execution added pinned
SHA-256 support and promoted UUID to a normal dependency. Do not adopt the synchronous
test loader as a universal distributed driver interface.

Generated snapshots and databases use a newly created run directory under
`rebase-next/target/native-slice/`; Cargo reuses `target/native-slice/build/`.
Fail on an existing or aliased run path; never fall back to the original
configuration/store or use a general reset. Close handles and clean only owned
per-case database directories on success/failure; retain observation reports.
Source inputs, old evidence and the build cache remain outside that cleanup.

During implementation, run the smallest changed boundary check. Once Rust pieces
are integrated, run the locked suite, formatting and Clippy appropriate to those
files. Broaden only after a new failure/connected capability justifies it. Do not
rerun original ReBase/MetaSol acceptance or the old example to inflate evidence.
Record candidate counts, formula evaluations, node/key loads, staged patches,
final dirty keys/bytes and checker coverage separately. No throughput claim or
arbitrary speedup target follows from these counts.

## 9. Deferred responsibilities and packet evidence

The [system audit](06-system-audit.md#4-what-a-stack-change-affects) still owns the
impact map. This slice replaces only the fixed calculation/tree/reference work
in its fixture. Its strict decoder and privileged raw observer are the immediate
developer tools. Build/explain/public catalogs, fixture tooling beyond these
cases, live inspectors, RPC, frontend bindings, principal DAGs, full accounting,
production decimal policy, receipts/audit/effects, range overlays, prefix/output
settlement, migrations and distributed schedules retain their named gates.

The original planning packet inspected the relevant Rust proof and M6 implementation,
verified all 12 pending M6 output hashes and all 11 original proof inputs, and
prepared this plan. The [dated evidence](evidence/2026-10-22-native-slice-plan.json)
records documentation/scope checks, inputs and exclusions. No native case had
executed then. The later [execution evidence](evidence/2026-10-22-native-slice.json)
records the completed stages and exact acceptance scope. The original evidence
must not be rewritten to describe the later implementation.
