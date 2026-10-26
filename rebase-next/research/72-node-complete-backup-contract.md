# N6 first checkpoint — source and complete backup checking

Accepted within the scope below on 2026-10-26: all 131 Node tests pass, with no
failures or skips. [Evidence](evidence/2026-10-26-n6-complete-backup.json) records
the exact source, command and native artifact. The focused implementation run
passed 26 tests; independent review replayed the private-record corruption
controls against real captures. No Rust build or native format change was needed.

This checkpoint composes the existing independent source oracles with N5's
physical tree checker for Equipment, Quantity and Measurement. It does not
change native semantics, codecs, wire identities or stored data. The remaining
N6 ingress, accounting workflows, bootstrap and deletion controls remain owed.

## API and evidence boundary

`checkSourceBackup({ model, facts, backup, roleHistory })` accepts authored source
facts and raw complete backup bytes (`Uint8Array`, including `Buffer`) or a UTF-8
string. Unsupported input types and byte lengths above 64 MiB are rejected before
allocating a snapshot copy. It retains a copy of the bounded bytes,
checks the existing bounded envelope, checksum and strict JSON codec, and derives
records, roots, queries, roles and reserved identities from those bytes. Logical
and physical observations therefore come from one image. No separate inspect
capture, native checker result, maintained native summary or production formula
is an authority for expected source values.

The existing `checkBackupStructure` accepts `includeObservation: true` to return
that semantic projection. `expectedRoots` is a `Map` from `uuid/slot` to
`{ kind }`; it checks the exact physical root inventory, including empty roots.
The existing `expectedMembers` map binds every physical node to an independently
expected address, root, time and leaf value. The source composition makes a second
bounded pass over the identical retained bytes with both expected inventories.
It reuses the same decoder and structure checker; it does not capture a second
store image.

Equipment Delivery members use source identity/17. Each active reservation has
two generated output identities with member slot 23, including zero allocations.
Source-only allocation determines their expected values. Producer-role bindings,
private output provenance and reserved inverse rows must be bijective.
Private output input objects must exactly match source-derived producer, role,
pool, decimal-string time and decimal-string quantity, with `derived: null`.
Extra input fields, numeric substitutes and invented derived payloads fail.
Measurement Observation members use source identity/17. Both models own root slot 7; Quantity
has no physical roots or members. The physical checker validates complete
`(time, UUID bytes, member slot)` ordering and independently folds the source-bound
leaves. This verifies Equipment prefix extrema at mixed-sign equal-time keys
without pretending that inspect exposes their order.

Measurement root and report-query statistics use the native plain
`{ count, sum, min, max, dimension }` shape. Latest-query `result` is the complete
selected observation or `null`: identity, member slot, time, unit and value.
The separate descriptor `selected` field is always `null` for this index family.
Expected range statistics and selections come from the existing authored-fact
scan, including empty ranges, inclusive/exclusive endpoints and equal-time ties.

`checkSourceSnapshot` still reports unavailable tree obligations as incomplete.
Complete backup checking replaces those obligations only after source membership
and exact root inventory pass. Native `store.check` remains a separate control.

## Retained role identities

Current facts cannot establish all reservations made by an inactive or deleted
producer. Optional `roleHistory` is an explicit trusted caller-owned identity
witness, an array of `{ producer, role, output }` rows. It lists every previously
allocated binding, including currently active bindings. Retain and merge these
identities from committed observations as the authored trace advances; do not
derive their expected IDs from the final image being checked. The checker does
not manufacture a UUID allocation algorithm.

When supplied, the witness must match the exact binding inventory and stable
output identities, with unique producer-role pairs and unique outputs. A live
producer has nonretired bindings; an absent producer has retired bindings. An
inactive or deleted producer has no surviving output record or physical output
member. Reserved rows must provide the exact inverse binding. Without a witness,
complete Equipment backup checking leaves the named `role-history-inventory`
obligation incomplete, even when all observed bindings have active producers.
Active output provenance and physical membership are still checked. An omitted
witness cannot establish the
absence of deleted historical bindings; callers needing historical completeness
must supply their retained witness, including an explicit empty array where
appropriate.

The witness is bounded at 16,384 reservations. Source-oracle limits are 4,096
Equipment facts, 64 Measurement facts and 16 Quantity facts. Existing backup byte,
row, tree-depth and node bounds remain in force. This is a bounded verification
composition, not a capacity result.

## Acceptance controls

`test/n6-complete-backup.test.mjs` captures real SDK-free native backup bytes for
all three models. Equipment covers equal-time mixed signs, zero outputs, empty
roots, retargeting, deactivation/reactivation, deletion, stable reservation
identities and rejected producer-ID reuse with complete image preservation.
Measurement covers equal-time latest identity ties, range boundaries, empty
statistics and absent selections. Quantity covers exact arithmetic including a
zero-factor dependency and empty physical inventories.

Counterexamples include self-consistent physical trees with source-inconsistent
times or dimensions, an extra empty Quantity root, changed query selection fields,
changed derived values, duplicate and changed identity witnesses, and malformed
root inventory expectations. Unit controls reject each altered Measurement query
payload field and the former invented Measurement summary envelope.

Only source records, source-derived values, query descriptors, role/reservation
identity, expected roots/members and physical trees are covered. This does not
claim a complete independent decoder/checker for authority, receipts, effect
runtime, registrations, reverse edges or other native KV inventories. Backup
material can contain private runtime data; tests use disposable owned stores and
remove them after closing their native hosts.
