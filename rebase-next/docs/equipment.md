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

## Run with the existing tools

Build the binary and configure issuer keys, a token and `server.json` using the
[server guide](server.md). Select equipment before each command that reads its
model or opens its store:

```sh
rebase-next --model equipment model public
rebase-next --model equipment model explain Reservation
rebase-next --model equipment init equipment.redb --tenant 00000000-0000-4000-8000-000000000001 --actor 00000000-0000-4000-8000-000000000002
rebase-next --model equipment fixture plan equipment --namespace 00000000-0000-4000-8000-000000000100 > equipment-draft.json
rebase-next --model equipment serve equipment.redb --config server.json
```

In another terminal, submit the draft through the existing stateless client:

```sh
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt prepare equipment-draft.json equipment.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt apply equipment.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt status equipment.plan.json
```

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

```sh
rebase-next --model equipment check equipment.redb
rebase-next --model equipment inspect equipment.redb --html > equipment.html
rebase-next --model equipment backup equipment.redb equipment-backup.json
rebase-next --model equipment restore equipment-backup.json restored-equipment.redb
```

One process owns a live redb file. Backup and restore destinations must be new.
The equipment `demo` command is unsupported; its fixture and the ordinary client
provide the workflow. Bounds are 4,096 public records, 8,192 active outputs and 16,384
retained output identities, plus shared mutation/query/receipt budgets. Every
active reservation requires two outputs, including when allocation is zero.
One pool and three deliveries therefore leave room for 4,092 reservations.
Each mutation still has at most 64 commands, 32 returning IDs and 200,000 charged
engine work units. Endpoint indexes avoid opening unaffected subscribers, while
full fanout may exceed that budget and reject atomically.
See [compiled model authoring](compiled-models.md) for the trusted Rust interfaces
and declared-shape boundary.

Run the source-arithmetic HTTP population probe for equipment alone with:

```sh
python3 -B tools/capacity.py --binary target/native-slice/build/release/rebase-next --out target/my-equipment-capacity --models equipment
```

It defaults to 64, 256, 1,024 and 4,096 public sources. Omit `--models equipment`
to include calculation. Results retain loaded bytes, selector work, fanout
outcomes and rollback checks, plus lifecycle, authority, replay, pages and
restart/restore controls. See the [population result](../research/24-population-scaling-result.md)
for executed evidence. Release 0.4.0 equipment behavior is
`equipment-reservations-3`, on store/codec format 4; earlier format 3 stores
require their matching old binary and have no implicit migration.
