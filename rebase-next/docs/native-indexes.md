# Native indexes and dimensioned measurements

A compiled model selects one `Binding::Index` family. The shared linked AVL owns
occurrence ordering, balancing, neighbours, subtree spans, work limits, revisions
and storage. Each family supplies native keys, leaves, summaries, query results, a stable index
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
| ObservationReport | 307 | `{"instrument":"<canonical UUID>","range":{"lower":{"included":"0"},"upper":{"excluded":"20"}},"unit":7,"threshold":"5"}` |
| LatestObservation | 419 | `{"instrument":"<canonical UUID>","at":"10","unit":7}` |

All listed fields are mutable through version-checked updates. Unit codes are
integers from 1 through 65535. Times are canonical signed i64 decimal strings;
values are canonical signed integer strings with magnitude at most `1000000000000`.
Leading zeros, `-0`, numeric times/values, extra fields and positional arrays
reject. No unit conversion is implicit.

An Instrument owns root slot 7, `observations`, using native index code 7. Each
Observation joins it through membership slot 17. Observations reference an
Instrument, and their reader follows the declared reference-owner policy.
Both consumers inherit their reader through the same reference and declare
their direct dependency on the Instrument's authored unit. They have no root,
membership or private output. The limit is 64 total public records, including
instruments, observations, reports and selectors. Existing models keep
their separately declared limits and the same mutation work budget.

The settled root must be empty or contain only observations whose unit equals
the instrument's unit. Changing the owner unit alone on a populated root rejects.
A batch may change the instrument and all observations together, in either
command order. The intermediate summary records mixed dimensions; final-state
validation accepts only the repaired result. Moving an observation repairs both
roots. Deleting the last observation produces an empty root; deleting a referenced
Instrument rejects unless the same batch removes or retargets its references.

## Reactive observation reports

An ObservationReport publishes count, minimum, maximum, unit and
`at_least_threshold` over its exact authored window. For `5 @0`, `12 @10` and
`-2 @20`, unit 7, window `[0,20)` and threshold 5, its ordinary record read has:

```json
{"count":2,"min":"5","max":"12","unit":7,"at_least_threshold":true}
```

Moving the last observation to time 15 changes this to count 3, minimum -2,
maximum 12 and false. An empty window returns count 0, absent extrema and false,
even for a negative threshold. The reported unit remains the authored unit;
it must match the Instrument. Deleting all members or making an equal-result
edit retains the query and its exact dependency window. Changing only an empty
Instrument's unit can still reject because its report depends on that unit.
Joint Instrument, observation and report repairs use the final batch state.

The report declares query slot 31, operation `summary`, channel `statistics`,
calculation phase, and Instrument root slot 7. The family supplies its strict
native Summary to the shared scheduler. A literal source checker reconstructs
the result and every direct/subscriber registration independently. Final authored
observations are the candidate universe; managed statistical emissions and reads
from selected records' published values are separate capabilities.

The report's own Read grant governs its materialized value. Revoking Instrument
Read does not redact an existing readable report. Creating or retargeting a report
still requires the normal authority to reference the Instrument; revoking report
Read hides it from record reads, pages and replay disclosure.

The fixture and independent integer/HTTP workflow use ordinary APIs:

```sh
rebase-next --model measurement fixture plan observation-report \
  --namespace 00000000-0000-0000-0000-00000135295f
python3 -B tools/observation_reports.py --binary target/g4db-accepted/rebase-next \
  --out target/my-report-workflow
```

## Latest authored observation

LatestObservation publishes `{"selection":null}` if its Instrument has no
Observation at or before `at`. Otherwise `selection` contains the authored
occurrence's identity, member slot, time, unit and value:

```json
{"selection":{"identity":"00000000-0000-0000-0000-000000000015","member_slot":17,"time":"10","unit":7,"value":"12"}}
```

The greatest complete `(time, UUID, member slot)` wins. Every observation at the
exact cutoff participates; ties never depend on insertion order. Equal values
with different identities are different selections. The dependency covers all
`(-infinity, at]`, including absence. Inserting a first candidate, rekeying,
moving or deleting the winner, and changing nonwinners all use that declared
window. A nonwinner edit can evaluate the selector while preserving its version
when the complete selection is unchanged.

Query slot 43 uses operation `latest`, channel `observation`, calculation phase
and Instrument root 7. The shared predecessor traversal returns a native
occurrence, which the family converts into its typed result. Public statistics
root reads remain as listed below; this consumer does not add a quote adapter.
Its own Read grant controls materialized results, including record pages and
replay. Creating or retargeting it still requires authority to reference the
Instrument. Unit checks, retargeting and joint repairs use the final batch state.

```sh
rebase-next --model measurement fixture plan latest-observation \
  --namespace 00000000-0000-0000-0000-00000135295f
python3 -B tools/observation_selection.py --binary target/g4dc-accepted/rebase-next \
  --out target/my-selection-workflow
```

The fixture includes a report and equal-time candidates. The workflow compares
both consumers against authored facts, then verifies authority, complete
rollback, reopening, a process kill and restore. Candidate observations are
authored records. Managed candidates and reads from a selected record's
published fields remain separate capabilities.

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

`NativeIndex::QueryResult` owns persisted calculation values. Family methods
validate operation/phase/channel, map native summaries or selected occurrences to results and select
shared scheduler participation. `Query<Index>` and the complete storage checker
use that same compiled type. Serialization hooks preserve Standard's existing
decimal-string `i128` results. Measurement uses strict disjoint summary and
optional-selection variants; summary bytes remain unchanged. Native query
support is declared independently of the public root-read names. Public JSON
projections remain separate. The existing financial prefix path and
nonnegative terminal validation are explicit adapters. Generic managed statistics
emissions are not supplied by this port.

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

Source 0.14.0 uses store 9 /native codec 6 /effect codec 3 /API 3. Authored selection
changes measurement's behavior to `dimensioned-measurements-3`; other model
identities and existing Standard query bytes remain unchanged. Report summary
and derived encodings are preserved. Keep older measurement stores with matching
binaries; there is no implicit populated-store migration. See
[storage identities and upgrades](storage.md#data-identity-and-upgrades).
Behavior revisions cover algebra, ordering, projection and invariant semantics;
descriptor hashes supplement that explicit contract.

Variance, percentiles, rank/select, compound-prefix bounds, unit conversion and
managed statistical emissions require separate capabilities. This gate does
not establish arbitrary query-result scheduling, unrestricted population capacity
or a new deployment bundle.
