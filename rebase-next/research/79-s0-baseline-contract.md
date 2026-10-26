# S0.0 — bounded baseline contract

This checkpoint freezes S0.0 only, after accepted documentation `b34237c`.
It is based on native source `1243168424294728968591d69efbe5d836fd36fd`,
whose 89-input native digest is
`1354c9fa93c2cb7108f974a03f978c0f491da3ec3dc22ecebf6d3aa35846d616`.
No instrumented executable or measured result exists.
The baseline remains the existing AVL and unchanged transactional semantics.

## Checkpoints

S0.0 checks this contract, the [plain JSON manifest](fixtures/s0-workload-manifest.json),
[literal inputs](fixtures/s0-inputs.json) and [trace shape](fixtures/s0-trace.schema.json)
against source.
It changes no native runtime/storage code and requires no Cargo build.
The Node evidence checker is executable tooling. S0.1 adds bounded optional
instrumentation and focused tests. S0.2 runs the frozen local baseline, publishes
raw samples and aggregates, and explicitly records missing multi-host evidence.
S1 candidate layouts, selection thresholds and migrations are outside S0.

The manifest records an experiment; ordinary Rust/Node functions implement it.
It is not a second workflow/query language or a general manifest interpreter.
One Rust example may use normal Cargo example arguments to select backend,
owned location and report path. Node calls existing infrastructure functions,
uses `spawn` with an argument array where required, and reads/writes normal files.
There is no project CLI parser, environment hotkey, global registry or RPC change.

## Measurement path and scope

The direct Rust probe opens real storage adapters, creates real encoded native
state, and calls existing `Attempt`, `tree` and native Calculation settlement
functions. It uses one adapter transaction for an action and its staged writes.
This does not measure authenticated HTTP, Store receipt/authority bookkeeping,
or Node RPC overhead. Every report names this exclusion. Existing native Store
application checks provide a separate tiny correctness control, outside timing.

Use ordinary `Database::begin_read_diagnostic(trace)` and
`begin_write_diagnostic(trace)` methods, backed by default Backend methods that
retain current behavior. A thin scoped ReadView/WriteView wrapper records facade
calls; FDB overrides create instrumented transactions and records binding calls.
Normal begin methods and the production server retain existing paths. The
recorder is an explicitly passed handle owned by one transaction/action, never
authoritative state. No new retry, batching or cache policy is introduced.

`Attempt` accepts an optional diagnostic recorder. Count ensure entries, cache
hits and misses there; a successful miss populates the Attempt's typed cache.
Preserve existing Work fields and work-unit charging exactly. In particular,
`key_loads` counts charged load attempts, not every touch or SDK request;
`loaded_bytes` excludes keys and missing values; `encoded_bytes` counts encoded
dirty value bodies. Trace counters must not become enforced work-budget units.

Facade GET/scan/put/remove counts do not mean physical disk operations. An FDB
table GET may issue a catalog GET and a data GET; one facade scan may issue many
`get_range` invocations. Record each actual binding call, its role, key/value
byte counts and elapsed time. Never call them packets, network requests or RTTs.
Map official FoundationDB 0.11 TransactionMetrics fields explicitly: its
`call_get` counts point GETs; `GetRange` contributes rows/bytes but does not have
a dedicated range-call field. The wrapper supplies that separate invocation count.
Official metric bytes and independently counted adapter bytes retain distinct
names and definitions; equality is asserted only when their definitions agree.

## Bounded event graph

Each event has a monotonically assigned ID, monotonic start/end nanoseconds,
layer, operation, parent scope, outcome, row/byte counts, and optional key token.
Use SHA-256 of encoded keys, scoped by action identity, with no raw values.
Events nest Attempt loads, facade operations and binding calls. Nonoverlapping
operations also record an execution predecessor; this is scheduling evidence,
not a key-discovery dependency. FDB catalog existence checks may gate data reads
while their data key was already known. Represent this as a control edge,
separately from a result-discovered key edge.

The probe explicitly seeds keys supplied by its invocation. For the tree scope,
observe addresses in decoded Root/Node values at the point that their load
completes; retain each key's earliest known source. Child/parent/neighbour keys
carry a result-discovery edge only if they were first learned from that result.
A repeated reference to an already known key retains its earliest provenance.
`initialKeys` declares invocation/generated/cache keys, while found load events
list bounded `discoveredKeyTokens`. Edges must match that first-known witness.
These are recorder witnesses, not independent proof of decoded native values;
S0.1 must test that actual Root/Node fields produce these tokens faithfully.
Constructed/staged keys are marked locally generated. A complete tree trace must
account for every requested key; unknown provenance makes its dependency metric
incomplete. Native settlement may have partial lineage until all relevant record,
route and causal discoveries are instrumented; report null with a named reason.

`observedReadDepth` is the longest key-discovery chain of Attempt load events in
this phase, counting an initial load as one. Wrapper/binding events and catalog
control edges are recorded separately and do not add to that metric. It describes
native key discovery; no field claims measured remote/network rounds.
For the repeat traversal, previously loaded typed entries satisfy reads locally;
report zero backend requests and the work delta for that phase. Do not pretend
the original transaction's historical reads occurred again.

Per action retain at most 4,096 events, 4,096 key provenance facts and 1 MiB of
serialized trace data. Counts continue within fixed-size counters after overflow;
event/provenance overflow sets `complete:false` and an explicit reason. Each
report is bounded to 64 MiB and the run to ten minutes per backend. Reaching a
bound ends admission and preserves completed and unknown actions. No silent
truncation or unbounded stderr/maps. Stop immediately on correctness mismatch.

## Workload facts and cache phases

The manifest freezes a small representative source corpus, not S1's full matrix.
For an Entry, the actual maintained member is slot 1 in Account root slot 2:
`m=1`. A Posting has member slots 1 and 2 in Account/Subsidiary roots: `m=2`.
A Rule edit with exactly 1 or 4 dependent Postings provides a real bounded
recalculation closure; `r` counts distinct dependent records excluding the edited
Rule. Record actual affected root addresses, per-root before/after membership,
affected member slots and recalculated record IDs; check them against input and
decoded state. No fake Cartesian product of n/m/r is generated.

Tree queries operate on the native state from Entry inputs. Prefix/range results
are checked by an independent sorted fold of input facts, written without
production tree traversal, native cached summary combination or settlement.
Positive Entry amounts make the tiny setup invariant-safe. Posting cases use
small literal integer units, c and rate; independent expected native/reporting
amounts use their explicit products. Retain inputs, expected results and result
checks with raw timings. Retired native-slice fixture `_expect` is not an oracle.

Attempt-first means the first traversal through a new empty Attempt cache.
Attempt-repeat means the identical read-only traversal in that same Attempt and
transaction. Snapshot Work/diagnostic counters around each phase and report
deltas. Mutation samples start new transactions; never replay a mutation just
to claim a warm Attempt. Reset sample input through unmeasured owned setup.
Keep process/backend/OS/client cache state separate. A fresh transaction is not
a cold OS or disk cache. One explicit unmeasured setup traversal warms the process;
the first measured transaction remains Attempt-first.

First run one pilot sample per selected action/backend. Keep pilot samples
separate and verify correctness, trace size and estimated final duration against
the existing bounds before admitting the 30-sample campaign. If the estimate
exceeds a bound, stop with incomplete evidence and freeze a smaller explicitly
revised manifest before another run. Measure instrumentation overhead separately:
30 matched trace-off/on pairs of the n=8 prefix case per backend, alternating
order, with identical transaction boundaries and process warmup. Report both raw
latencies and paired ratios; this bounds overhead only for that named case.

Run at concurrency one on redb, local FDB and standalone SurrealKV. Retain every
raw operation result, outcome and nanosecond duration. Report n, nearest-rank
p50/p95/p99 and minimum/maximum per identical action/backend/cache phase; with
30 samples p99 is the maximum and carries no tail-capacity guarantee. Setup,
correctness checks, commit time and traversal time have distinct fields. Preserve
definite abort, conflict and unknown commit outcomes and original action identity;
no automatic adapter retry or expired-plan refresh. Missing counters remain null.

Counters use a named primitive layer: binding on FDB, facade on embedded adapters.
Returned rows and read/write key/value bytes sum that layer once, including FDB
catalog/guard work. Facade invocation totals remain separate. A zero means an
observed supported counter saw no calls; unsupported/uncollected binding or SDK
metrics are null with incomplete evidence. Sample resources outside timed spans
using existing Node observation and OS information; retain process CPU/RSS, disk
space and versions with explicit availability. No new metrics framework.

The [ordinary checker](../tools/node/examples/s0-contract.mjs) compiles the schema
with the existing Ajv factory, then checks semantic obligations: unique event IDs,
scope containment, ordered times, earlier completed discovery/control sources,
key-discovery depth and event-derived counts. Its tests include valid nesting,
known independent keys, false dependencies, missing IDs, bad counts and truncation.
Schema validation alone does not prove these facts. Report files are private owned
artifacts; public logs contain action IDs/status only, never raw keys, fields,
values, credentials or complete source payloads. Unknown outcomes preserve the
original action/operation ID, exact commands, versions and allocation history.

## Source-bound acceptance

S0.0: strict schema/manifest validation, concrete source references for dimensions,
event edge definitions and bounds, unchanged executable fingerprints; no timings.
S0.1: deterministic checks for cold/repeat cache deltas, independent known keys
versus discovered child keys, unknown lineage, overflow, multiple range iterations,
catalog/data separation, failure and commit classifications. Focused native tests
plus the real tiny application rollback control; unchanged formula/format identities.
S0.2: exact executed source/build/dependency hashes, hardware/topology/limits,
complete raw samples, independently checked results, trace completeness and
cleanup. Reuse accepted unaffected controls by identity, not by relabeling binaries.
Actual multi-host FDB remains incomplete unless real infrastructure is available.
Missing lineage is also incomplete; useful counter measurements do not turn it
into a dependent-round result or unrestricted capacity acceptance.

Planned maintained files: this research contract, a research JSON manifest and
trace schema, `src/diagnostics.rs`, `src/storage.rs`,
`src/storage/foundationdb.rs`, `src/native_slice.rs`, `src/lib.rs`, and
`examples/s0_baseline.rs`; a small example-local independent oracle may be split
out if it improves review. Node orchestration should stay an ordinary example
composition of current functions, not a new SDK or parser surface.

Native source anchors: [Attempt](../src/native_slice.rs),
[tree functions](../src/tree.rs), [declared memberships](../src/model.rs),
[FDB primitive calls](../src/storage/foundationdb.rs), and the
[tiny application rollback control](../src/storage/application_checks.rs).
The S0.0 tests validate frozen inputs and proposed trace examples; they do not
execute those native operations. S0.1 must compile/check the exact commands and
oracles before timing. No formula, format, budget or retry semantics change here.

Focused S0.0 validation: ordinary Node contract tests check eight literal corpora
and their manifest selections, source-derived dimensions and action expectations,
plus trace shape/graph/counter controls. No native workload has been executed.

## Preparation limits and exact continuation

The checker verifies source dimensions, member amounts, commutative totals,
bounded trace shape, recorded key witnesses and event-derived call/byte counters.
The independent full-key ordered fold, count and prefix extrema remain S0.1
work. Consistency between declared success/abort/conflict/unknown outcomes and
real commit events also remains pending. Node/selector Work counters and the
fidelity of decoded-key disclosures require native controls: a recorder witness
alone does not independently prove which addresses a private value contains.
Do not call these pending controls passed from synthetic trace examples.

This session stops after the preparation commit at the user's request. The next
agent should finish S0.1 instrumentation and these obligations, then run the
declared pilot before S0.2. No performance or layout conclusion is accepted.
