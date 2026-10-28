# Equipment reservation model

The equipment model uses the same prepared-model interface, mutation transaction,
principal DAG authority, role lifecycle, queries, receipts and storage adapter as
the calculation model. Select one compiled model for a store; their identities
are incompatible. It is a bounded equipment allocation example, not a scheduling
optimizer or a dynamically loaded extension.

A Pool owns availability history. A Delivery adds nonnegative units at a time.
An active Reservation reads availability strictly before its start and allocates
`min(requested, max(0, available_before))`. Its two private outputs consume units
at the start and release them at the end. Both outputs retain fixed role identities
through deactivation and reactivation. End must follow start. Integer quantities
are bounded at one million; times use canonical i64 decimal strings.

With 10 units delivered at time 0, A requesting 8 over [10,30) receives 8;
B requesting 7 over [20,40) receives 2. Increasing delivery to 12 gives B 4.
Moving A's end to 15 gives B 7. Deactivating A removes its outputs; reactivation
restores them. Moving A to another pool with 6 units clips A to 6 and leaves B 7.

Queries and output positions depend only on authored fields. Calculated results
change output quantities, never their slots or topology. Simultaneous starts read
the same strict prefix; if their combined allocation exceeds availability, final
complete-time validation rejects the atomic mutation. Same-time events are grouped
for that invariant. This bounded policy intentionally has no tie-breaking allocator.

The independent checker scans public sources, derives event arithmetic in start
order, and compares published values, private output payloads, query registrations,
actual tree memberships and summaries. It does not call settlement or tree queries.
Sparse contract/root/member/query/role codes exercise the reusable engine boundary.

## Current use

Choose `model: "equipment"` in the native model configuration and configure the
HTTP service using the [server guide](server.md). Legacy CLI and Python fixture
commands are retired. The [N2 equipment example](../tools/node/examples/n2-equipment-workflow.mjs)
shows the current caller-owned JavaScript composition:

The [N2 Equipment example](../tools/node/examples/n2-equipment-workflow.mjs) shows the current caller-owned model, client and operator composition.

The draft includes deterministic UUIDv5 identities under `fixture.ids`, public
commands, returning IDs and literal expected allocations. A different namespace
creates another instance. Fixture planning does not write data. Keep the saved
plan for retries; author a new operation for a new intent. The client obtains
model and operation context from the destination and fences the saved request.

Use `call records.get params.json` to obtain a reservation's current version,
then author an ordinary update draft. `roots.read` reads Pool root slot 7 with
`{"kind":"summary"}` or `{"kind":"before","at":"21"}`. For the initial fixture,
strictly before 21 the sum is `"0"`; after delivery increases to 12, B's allocation
becomes `"4"`. Contract codes are Pool 101, Delivery 205, Reservation 410 and
private EquipmentOutput 900. Public catalogs omit the private contract; developer
inspection can explain its role declarations.

After stopping the HTTP process, the same model selector applies to operators:

The [N2 Equipment example](../tools/node/examples/n2-equipment-workflow.mjs) shows the current caller-owned model, client and operator composition.

One process owns a live redb file. Backup and restore destinations must be new.
The equipment `demo` command is unsupported; its fixture and the ordinary client
provide the workflow. The model has no configured fixed population ceiling, and
population counters are u64. Every active reservation requires two outputs,
including when allocation is zero. Shared limits remain: a 262,144-row
observation budget for full inventory and check operations, 64 commands, 32
returning IDs, 200,000 charged engine work units, 128
query visits, 1,024 receipts, and 64 MiB per backup. Endpoint indexes avoid
opening unaffected subscribers, while full fanout may exceed the work budget
and reject atomically. Redb-connected end-to-end checks cover 5,001 and 10,001
records in scoped tests; this does not establish unrestricted or production
capacity.
See [compiled model authoring](compiled-models.md) for the trusted Rust interfaces
and declared-shape boundary.

The historical source-arithmetic HTTP population probe covered these sizes:

The [N2 Equipment example](../tools/node/examples/n2-equipment-workflow.mjs) shows the current caller-owned model, client and operator composition.

It measured 64, 256, 1,024 and 4,096 public sources. Results retained loaded bytes, selector work, fanout
outcomes and rollback checks, plus lifecycle, authority, replay, pages and
restart/restore controls. See the [population result](../research/24-population-scaling-result.md)
for executed evidence. Release 0.4.0 equipment behavior is
`equipment-reservations-3`, on store/codec format 4; earlier format 3 stores
require their matching old binary and have no implicit migration.
