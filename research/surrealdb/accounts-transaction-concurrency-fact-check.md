# Accounts Movement And Concurrency Fact Check

Status: measured engine behavior and adopted Accounts design boundaries
Last reviewed: 2026-09-08

This document records the raw SurrealDB behaviors that constrain the Accounts
movement redesign. It is deliberately narrower than the all-in-one suite
plans. It covers writable position anchors, materialized views, synchronous
events, concurrent movement writes, temporal replay, polymorphic references,
and the delete behavior needed by money, inventory, service, and tax facts.

The raw-material measurements were first isolated from the application
schema. The current Accounts probe also applies the adopted replay event to a
disposable copy of the all-in-one schema, so implementation regressions are
covered without treating the probe database as production data.

## Executive findings

| Question | Finding | Classification |
| --- | --- | --- |
| Can a materialized view row be updated as an OCC anchor? | No. `CREATE` and `UPDATE` against a table defined with `AS SELECT` fail as read-only. | Measured / rejected |
| Can a view event reject a source mutation? | Yes. A synchronous view event can throw; the source row, view maintenance, and event writes roll back together. | Measured / adopted |
| Can a mutable position row provide a write conflict boundary? | Yes. Concurrent source events updating one position produce retryable transaction conflicts. | Measured / adopted |
| Does a two-leg movement update both positions atomically? | Yes. One leg conflict leaves no source movement and no partial position update. | Measured / adopted |
| Is a current aggregate enough to validate every historical prefix? | No. An old effective-time prefix can be negative while the final total is positive. | Measured / mathematical consequence |
| Can SurrealQL fold an ordered partition for replay? | Yes, `array::fold` over an ordered subquery worked. It materializes the affected partition and is not O(1). | Measured / bounded use |
| Can a synchronous event on an internal replay row reject a source edit? | Yes. The source event upserts a deterministic `position_entry`; its table event folds the provisional partition and rolls the source/position/entry writes back on a negative guarded prefix. | Measured / adopted |
| Can a client change the business effective time after creation? | A `READONLY` datetime field rejected the update. | Measured / adopted |
| Does `REFERENCE ON DELETE UNSET` clean an array reference precisely? | Yes. Only the deleted member is removed; the holder survives. | Measured / adopted |
| Does `REFERENCE` alone prove a target exists on input? | No. Pair it with an explicit `record::exists` assertion where existence is required. | Measured / adopted |
| Can a no-op write to a view force OCC? | No, because the view is not writable. Use a semantic update to a mutable position row. | Adopted |
| Can one scalar FX amount safely update unlike-currency positions? | No. The Accounts kernel uses a separate `money_exchange` fact with explicit source/destination amounts and an immutable FX snapshot. | Adopted |

## Probe environment

The focused probes used a disposable on-disk SurrealKV database. No `mem://`
datastore was used.

```text
SurrealDB 3.2.4+20260803.93ab219
surreal binary: /tmp/surreal
surrealdb JavaScript SDK: 2.0.8
Node: v18.19.1 (local limitation; the repository requires Node >=20)
storage: temporary surrealkv directory, removed after every run
transport: WebSocket with the `ws` constructor shim for Node 18
```

The baseline catalog, permission, view, time, statistics, and reference
measurements remain in:

- [`schema-temporal-fact-check.md`](./schema-temporal-fact-check.md)
- [`temporal-integrity-dimensional-fact-check.md`](./temporal-integrity-dimensional-fact-check.md)
- [`record-references.md`](./record-references.md)

The local reproduction pattern was:

```sh
PATH=/tmp:$PATH node <disposable probe using surrealdb + ws>
```

The probe started `/tmp/surreal start surrealkv://...`, authenticated as root,
created a fresh namespace/database, defined only the tables needed for the
assertion, and inspected the final statement result explicitly.

## 1. Materialized views are projections, not lock rows

The probe defined:

```surql
DEFINE TABLE src SCHEMAFULL;
DEFINE FIELD grp ON src TYPE string;
DEFINE FIELD amount ON src TYPE decimal;
DEFINE TABLE OVERWRITE v_src AS
  SELECT grp AS grp, math::sum(amount) AS total
  FROM src GROUP BY grp;
CREATE src:a SET grp = 'x', amount = 10dec;
```

The view contained one row with `total = 10`. Each of these statements failed:

```surql
UPDATE v_src:[s"x"] SET total = 999dec RETURN BEFORE;
UPDATE v_src:[s"x"] SET total = 888dec RETURN AFTER;
UPDATE v_src:[s"x"] SET total = 777dec;
```

The server error was:

```text
Cannot write to the `v_src` table, as it is a view (defined with `AS SELECT`);
view tables are read-only and their records are computed from the source query
```

The source and view stayed unchanged. A view therefore cannot be used for:

- a compare-and-set row;
- a write-write conflict marker;
- a mutable balance cache;
- a place to store a revision merely by touching its ID.

The view remains useful as a read projection and as a synchronous event source.
Its read path and its write path must not be conflated.

## 2. View events can enforce a source invariant

The probe added a view event that threw when the grouped total exceeded a
limit:

```surql
DEFINE EVENT v_guard ON TABLE v_src
  WHEN $event != 'NONE'
  THEN {
    CREATE guard_log SET label = 'seen';
    IF ($after.total ?? 0dec) > 20dec { THROW 'VIEW_LIMIT'; };
  };
```

After the source total was `17`, creating another source row of `10dec` failed
with `VIEW_LIMIT`. The new source row was absent, the view remained at `17`,
and the `guard_log` insert was absent. This confirms the useful boundary:

```text
source mutation
  -> incremental view maintenance
  -> synchronous view event
  -> THROW
  -> source, view, and event writes roll back
```

This is appropriate for a lightweight current-state guard. It does not make
the view writable and does not provide historical prefix state.

## 3. Mutable position anchors serialize current-state acceptance

The probe used a source movement table and a mutable position row:

```surql
DEFINE TABLE position SCHEMAFULL;
DEFINE FIELD balance ON position TYPE decimal
  DEFAULT 0dec ASSERT $value >= 0dec;
DEFINE FIELD revision ON position TYPE int DEFAULT 0;
CREATE position:cash;

DEFINE TABLE movement SCHEMAFULL;
DEFINE FIELD amount ON movement TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD position ON movement TYPE record<position>;
DEFINE EVENT apply_movement ON movement
  WHEN $event = 'CREATE'
  THEN UPDATE $after.position SET
    balance += $after.amount,
    revision += 1;
```

Twenty concurrent creates targeted the same position. Without client retry,
only one request in a smaller eight-request run and one request in a larger
contention window committed; the other requests returned a structured,
retryable transaction conflict. With explicit retry on the conflict, all 20
deterministic movement IDs committed and the position ended at:

```text
balance = 20
revision = 20
movement count = 20
```

No lost update was observed. A movement whose event would make the position
negative failed the position assertion, and both the source movement and the
position update rolled back. The position row is therefore a valid current
state conflict boundary.

The position is still a derived operational projection. The movement facts
remain the rebuildable source of truth. A repair/reconciliation operation must
be able to recompute a position from its source partition.

## 4. Two-leg movements are atomic, but conflicts are expected

The probe used one source and one destination position:

```surql
DEFINE EVENT apply_leg ON leg WHEN $event = 'CREATE' THEN {
  UPDATE $after.from SET n -= $after.amount;
  UPDATE $after.to SET n += $after.amount;
};
```

Two simultaneous legs from the same source to the same destination produced:

```text
one committed leg
one retryable transaction conflict
source position = 3 (initially 10, one leg of 7)
destination position = 7
```

There was no partial source/destination update. This supports a single
transactional movement fact with multiple position updates. The runtime must:

1. use deterministic movement IDs or a unique idempotency key;
2. update endpoints in a stable order when more than two anchors are touched;
3. retry only structured transaction conflicts;
4. make a replay safe if the complete query is resent.

## 5. Retry and idempotency boundary

The installed SDK exposes `isRetryableConflict(error)` and query-level
`.retry()`. The SDK documentation is explicit that a retry resends the complete
query. That has two consequences:

- a single movement create with a deterministic ID is replay-safe;
- a non-idempotent create with an automatically generated ID can duplicate
  logical work if the caller retries after an ambiguous network failure.

The Accounts contract should use one of these forms:

```text
client supplies movement ID and CREATE ONLY uses it
```

or:

```text
unique idempotency key -> one movement record -> one position application
```

Provider-style external effects are not part of this Accounts phase. A
database conflict retry must never be confused with an external API retry.

## 6. Ordered temporal replay is possible, but not constant time

The probe used an immutable business timestamp and an event that folded the
affected partition:

```surql
LET $rows = (
  SELECT VALUE amount FROM movement
  WHERE partition = $partition
  ORDER BY effective_at, id
);
LET $state = array::fold(
  $rows,
  { total: 0dec, min_prefix: 0dec },
  |$acc, $value| {
    RETURN {
      total: $acc.total + $value,
      min_prefix: math::min([
        $acc.min_prefix,
        $acc.total + $value
      ])
    };
  }
);
IF $state.min_prefix < 0dec { THROW 'NEGATIVE_PREFIX'; };
```

The query language accepted `array::fold` over an ordered subquery. Creating a
movement that made a historical prefix negative threw `NEGATIVE_PREFIX` and
left the movement table unchanged. A `FOR` loop with `LET $sum += $value` did
not parse, and rebinding a `LET` variable inside the loop did not update the
outer value. Generated replay should use `array::fold`, not assume imperative
loop mutation semantics.

The fold materializes the selected partition. Its cost is proportional to the
affected suffix/partition and its memory use is bounded only if the generated
query imposes a budget. It is not a universal O(1) operation. For large hot
partitions, use checkpoints or a generated block-summary structure later.

The associative summary is:

```text
total = left.total + right.total
minimum_prefix = min(left.minimum_prefix,
                     left.total + right.minimum_prefix)
```

SurrealDB does not provide a generic incremental window implementation for
this summary. It must be generated and benchmarked as a domain-specific
optimization.

## 7. Effective time must be separate from system time

`DEFINE FIELD effective_at ... READONLY` accepted the initial datetime and
rejected an update to it. Accounts should therefore carry at least:

```text
effective_at  = client/business ordering, immutable
recorded_at   = system write/audit time, machine-owned
id            = deterministic tie-break after effective_at
```

An old transaction correction is an amount/endpoint change or a delete and
recreate operation that triggers replay. It is not an update to the ordering
timestamp. The current position can remain a fast operational projection, but
strict historical tables need revisions and ordered replay.

## 8. References and polymorphism

The existing reference probes establish:

- `record<item | service>` and other record unions parse and preserve the
  concrete table; `record::tb()` identifies the branch;
- `REFERENCE ON DELETE REJECT` blocks deletion of an in-use authoritative
  endpoint;
- `REFERENCE ON DELETE UNSET` on an array removes only the deleted member;
- `REFERENCE` is delete/reverse-link behavior, not an input existence check;
  use `ASSERT record::exists($value)` where a dangling endpoint is invalid;
- a non-reference provenance ID may intentionally dangle, but it must never be
  dereferenced in a guard or aggregate.

The Accounts rule is consequently:

```text
authoritative endpoint/context -> typed reference + explicit existence check
optional provenance/context   -> optional reference or opaque origin, never a guard input
```

Use explicit `record::tb()` branches for item/service, treasury/misc, and
other polymorphic semantics. Do not infer a type with a null-coalescing chain.

## 9. Dimensions and view cost

Grouped materialized views are sparse over observed tuples; they do not create
a full Cartesian cube. Every additional maintained view still adds source
write work, storage, and possible contention. The measured permission work in
[`reference-permission-performance.md`](./reference-permission-performance.md)
shows the same shape: native reverse references help only when the query uses
an explicit reverse path, and do not magically rewrite a permission table scan.

For Accounts, materialize only the positions and projections that enforce or
serve a repeated query:

```text
money position:       endpoint + currency
inventory position:   operating unit + item (+ lot when required)
service position:     operating unit + service
tax projection:       taxable line + tax direction + currency
```

Do not precompute every combination of organization, item, service, currency,
tax rule, and time bucket.

## Adopted and rejected policies

### Adopted

- Views are read-only projections and synchronous guard sources.
- Mutable position rows are the write conflict boundary.
- Movement facts are rebuildable source records.
- Current-state guards and historical replay are separate policies.
- Effective timestamps are immutable and ordered with a deterministic ID tie
  break.
- `array::fold` is the first replay primitive, with an explicit work budget.
- Native references plus explicit existence assertions protect authoritative
  graph edges.
- Currency, item, service, tax rule, and organization are explicit dimensions.
- Sparse, purpose-built views replace a universal cube.

### Rejected

- writing a materialized view row to obtain OCC;
- using a no-op ping instead of updating a semantic mutable anchor;
- treating a current sum as proof of historical validity;
- one universal transaction table with hidden cash/stock/service branches;
- treating tax as a divisor or as an automatic payment;
- using a generic context array as a replacement for payment allocation or
  other integrity-critical relations;
- relying on client retries without deterministic IDs or idempotency keys;
- claiming universal O(1) writes or replay.

## Required regression matrix

| Area | Positive case | Failure case |
| --- | --- | --- |
| View | source mutation refreshes aggregate | direct view write is rejected |
| View guard | limit event rejects source and rolls back | event-side log does not survive rollback |
| Position | one movement updates balance and revision | negative result rejects source and anchor |
| Concurrency | retryable conflict then deterministic retry commits | no lost or duplicate movement |
| Two legs | source and destination update together | conflict leaves neither leg partial |
| Replay | valid ordered prefix commits | late/edited row with negative prefix rolls back |
| Time | `effective_at` orders with `id` tie-break | effective timestamp update is rejected |
| References | delete-unset removes one array member | reject blocks authoritative endpoint deletion |
| Polymorphism | item/service branch resolves explicitly | dangling provenance is never dereferenced |
| Dimensions | only required sparse groups exist | high-cardinality view multiplication is measured |

Rerun this document's probes after every SurrealDB upgrade and after changing
any relevant `VALUE`, `ASSERT`, `REFERENCE`, view, event, or storage setting.
