# Native indexes and dimensioned measurements

A compiled model selects one `Binding::Index` family. The shared linked AVL owns
occurrence ordering, balancing, neighbours, subtree spans, work limits, revisions
and storage. Each family supplies native keys, leaves, summaries, a stable index
codebook, checked summary operations and exact schemas. Financial and quote
histories use `indexes::standard`; measurements use `indexes::measurement`.
Both use the same mutation, codec, integrity, authority and lifecycle paths.

The measurement model maintains count, sum, minimum, maximum and a uniform unit
for authored observations. For `5 @0`, `-2 @10` and `9 @10`, all in unit 7, the
root returns count 3, sum 12, minimum -2 and maximum 9. The closed window `[10,10]`
returns count 2 and sum 7. Equal-time observations remain separate occurrences.

## Run the model

Use `--model measurement` for every model/store command. The fixture is repeatable
for a supplied namespace and uses the ordinary developer-tool plan format:

```sh
rebase-next --model measurement model public
rebase-next --model measurement fixture plan measurements \
  --namespace 00000000-0000-0000-0000-00000135295f
```

Select the model when initializing and serving a store; the authentication and
configuration steps are the same as in [the server guide](server.md).
Use `tools/client.py` to prepare and apply the fixture through the public API.
The independent HTTP acceptance workflow creates its own secured store, issuer,
credentials and server, then retains its plans, backups and result:

```sh
python3 -B research/experiments/measurement.py \
  --binary target/native-slice/build/release/rebase-next \
  --out target/measurement-acceptance
```

Use a new output directory. The workflow stops all its owned processes. Its
`result.json` records executed checks; merely building the model is not evidence
that deployment acceptance has run.

## Public contracts

| Contract | Code | Complete authored input |
| --- | --- | --- |
| Instrument | 101 | `{"unit":7}` |
| Observation | 211 | `{"instrument":"<canonical UUID>","at":"10","unit":7,"value":"-2"}` |

All listed fields are mutable through version-checked updates. Unit codes are
integers from 1 through 65535. Times are canonical signed i64 decimal strings;
values are canonical signed integer strings with magnitude at most `1000000000000`.
Leading zeros, `-0`, numeric times/values, extra fields and positional arrays
reject. No unit conversion is implicit.

An Instrument owns root slot 7, `observations`, using native index code 7. Each
Observation joins it through membership slot 17. Observations reference an
Instrument, and their reader follows the declared reference-owner policy.
The model has no private outputs, formula queries or derived public fields.
Its limit is 64 total public records, including instruments. Existing models keep
their separately declared limits and the same mutation work budget.

The settled root must be empty or contain only observations whose unit equals
the instrument's unit. Changing the owner unit alone on a populated root rejects.
A batch may change the instrument and all observations together, in either
command order. The intermediate summary records mixed dimensions; final-state
validation accepts only the repaired result. Moving an observation repairs both
roots. Deleting the last observation produces an empty root; deleting a referenced
Instrument rejects unless the same batch removes or retargets its references.

## Read statistics

Use the ordinary authenticated `roots.read` method:

```json
{
  "model":"<model identity>",
  "owner":"<Instrument UUID>",
  "slot":7,
  "read":{
    "kind":"range",
    "range":{"lower":{"included":"10"},"upper":{"included":"10"}}
  }
}
```

The response's `value` is:

```json
{"count":2,"sum":"7","min":"-2","max":"9","unit":7}
```

`{"kind":"summary"}` reads the entire root. `{"kind":"before","at":"10"}`
reads strictly before 10. Ranges allow independent `included`, `excluded` and
`null` bounds, using the [exact-window contract](reactive-windows.md). Empty roots
and windows return `{"count":0,"sum":"0","min":null,"max":null,"unit":null}`.
An unreadable Instrument makes its root unavailable. A time adapter permits these
range reads; this family does not claim latest-quote or reactive scalar-sum support.

`model.describe` exports the public native index descriptors and exact result
schemas from the family used by the store. The persisted dimension representation
also distinguishes empty, uniform and mixed states; this internal algebra does
not add mixed-unit public results.

## Author and verify another native family

Implement `NativeIndex` with ordinary native Rust types and bind it through the
model's associated `Index`. Each stable, nonzero `IndexCode` describes its allowed
reads and key/leaf/summary/result schemas. Model preparation resolves root and
membership declarations against that family and incorporates the descriptors
into model identity. Optional time, financial and quote adapters declare actual
capabilities. A family can use non-Copy keys or non-time ordering without adopting
the financial value representation.

`FullKey<Key>` adds engine-owned UUID/member-slot occurrence ties to the business
key. Root/node spans are separate structural metadata. Summary functions provide
empty, singleton and checked associative combine operations; their bounded domain
must remain closed over every admitted subtree grouping. The measurement bound
keeps every sum representable at every grouping. A mixed dimension is a valid
intermediate summary, so final unit repairs do not depend on command order.

The independent checker derives membership identities and leaf values from
public source records. For each actual subtree, it scans those expected leaves
and compares the resulting summary, spans and links. It does not obtain expected
statistics from the writer's caches or call the writer's summary fold. Tests also
compare every parenthesization of short measurement sequences with a separate
literal scan, and run distinct valid AVL insertion orders through complete checks.
The HTTP oracle uses Python integer arithmetic over authored facts, exact boundary
filters, complete rollback snapshots and rehashed corrupted-backup controls.

Native index persistence uses store/codec 6. Keep older stores with matching
binaries; there is no implicit populated-store migration. See
[storage identities and upgrades](storage.md#data-identity-and-upgrades).
Behavior revisions cover algebra, ordering, projection and invariant semantics;
descriptor hashes supplement that explicit contract.

Variance, percentiles, rank/select, compound-prefix bounds, unit conversion and
reactive consumption of statistics require separate capabilities. This gate does
not establish arbitrary query-result scheduling, unrestricted population capacity
or a new deployment bundle.
