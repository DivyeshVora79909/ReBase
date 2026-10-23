# G4c result: a native index family behind one maintained tree

**G4c-a/b accepted, 2026-10-23, source 0.8.0 / store+codec 6.** The
[dated evidence](evidence/2026-10-23-g4c-native-indexes.json) records the active
single-tree port and dimensioned measurement model. Work resumed from `b377b21`;
the cloud partial changes were unavailable. The contract below retains the
design rationale and acceptance obligations. This is a source checkpoint;
the last accepted deployment bundle remains 0.6.0.

All 109 Rust tests pass in debug/optimized builds, formatting and Clippy pass,
and 68 foundation +39 causal +9 local cases pass independent source checks.
The measurement HTTP workflow passes 33 mutations /105 commands (26 commits,
7 complete rollbacks), reaches 64 sources and verifies authority, replay,
crash/reopen/restore plus six corrupt-index restore controls. Invoicing passes
111 mutations /340 commands. Measurement's full-capacity create/delete replacement
works in both command orders; orphan Standard roots report corruption through
check/startup/restore without panicking.

Calculation and equipment HTTP workflows pass at 64 and 4,096 sources. At 4,096,
zero/one-selection work matches G4b: equipment 24 selector visits, 45/54 key loads,
293/920 work units; calculation 24 visits, 21/51 loads, 87/198 units. Native spans
and envelopes increase stored/encoded bytes. Full fanout still rejects with
`work_limit`, complete rollback and no receipt. Bounds are unchanged; timings
from different hosts are not a performance comparison.

Three populated format-5 stores reject with physical bytes unchanged and remain
valid under the retained matching binary, rebuilt locally from `b377b21`.
The original cloud executable is not claimed as retained evidence. Native family
schemas/codes and behavior revisions bind prepared identity. The next selected
step is [G4d-a published values](36-value-dependencies-gate.md); custom reactive
statistics, selection and external effects remain unaccepted.

## Recommendation and the two concrete uses

Put the ordered index's native types and summary functions behind one ordinary
compile-time `Binding::Index` family. Port all existing indexes to the same
linked AVL implementation, then add a small useful measurement binding through
that implementation. Keep the existing time-window and scalar-sum scheduler as
explicit supported capabilities. Rich query results remain G4d.

The two motivating uses are:

1. **Existing financial history.** Signed exact deltas, ordered record-prefix
   extrema and complete-timestamp extrema must retain their current meaning.
   Equal-time releases/acquisitions and same-time monetary corrections already
   require a noncommutative summary. Quote selection must also survive the port.
2. **New dimensioned measurement statistics.** A public instrument owns a dated
   observation root. Each authored observation has an instrument reference,
   exact time, unit code and bounded signed integer value. Maintain count, sum,
   minimum, maximum and a uniform-dimension tag. Publish whole-root and time-window
   statistics through the ordinary authorized root API. Reject a final root with
   mixed units or a unit differing from its owner's declared unit.

For example, `5 unit-7 @0`, `-2 unit-7 @10`, `9 unit-7 @10` yield count 3,
sum 12, minimum -2 and maximum 9. The closed window `[10,10]` yields count 2,
sum 7, minimum -2 and maximum 9. An empty window has count 0 and absent extrema
and dimension. A unit-8 observation rejects atomically. Moving an observation
between compatible instruments repairs both roots; moving it to an incompatible
instrument rejects without a partial rekey or receipt.

Use a small declared starting population, for example 64 public sources, and a
conservative magnitude bound such as `abs(value) <= 10^12`. These are proposed
fixture bounds, not changes to production-model capacity. They keep every
subsegment sum representable regardless of tree regrouping. All arithmetic still
checks overflow. Missing measurements, variance, percentiles and statistical
inference are outside this first model.

This is a concrete new maintained summary and public operation, without first
requiring a new causal result language. It also exercises dimensions: a bare
numeric sum cannot establish the root's unit obligation.

## Options and maintained complexity

| Approach | Immediate work | Continuing ownership and author experience |
| --- | --- | --- |
| Add `Kind::Statistics`, `Leaf::Statistics`, `Aggregate::Statistics` to the core | Smallest isolated patch | Every new model summary spreads into tree, codec, model preparation, query projection and checker matches. This retains today's closed list rather than accepting a native extension seam. |
| Keep built-ins and let a binding maintain a custom tree in private KV | Avoids the initial port | A second writer, cache format, traversal, inventory and rollback/checking path must remain correct. Model authors inherit storage internals and tools cannot explain the new root uniformly. Raw KV writes are not an equivalent extension contract. |
| One AVL over a compile-time native index family | A coordinated initial port | Authors supply native types, bounded algebra, declarations and a source oracle. Balancing, point storage, revisions, budgets, authority and recovery stay shared. Existing models reuse one supplied family rather than rewrite it. |
| Separate monomorphized tree type per arbitrary runtime slot, with erased dispatch | Largest initial interface | Requires a heterogeneous registry, type erasure or generated dispatch before the second use needs it. Do not introduce this machinery. |

Choose the third approach. A binding remains trusted compiled Rust, already
selected when its store opens. Selecting its index family at compile time adds
no runtime plugin loader, custom parser, evaluator, automatic dependency capture
or callback registry. A model-local tagged enum is an ordinary way to represent
its finite mix of index values; adding a variant there does not extend a global
engine enum.

Keep explicit model hooks for exceptional business behavior. They must use the
same membership/tree primitives and inventory contract; an escape hatch must not
silently establish a second maintained-index engine. No new dependency is needed
for this gate. Continue using Serde, jsonschema and redb for their existing jobs.
`BTreeMap` is useful for temporary expected state; it does not replace a durable
point-addressed augmented index.

## Native type ownership

The proposed boundary is deliberately smaller than a general aggregate system:

```rust
trait Binding {
    type Index: NativeIndex;
    // Existing Input, Derived, declarations and trusted model hooks remain.
}

trait NativeIndex {
    type Key: Ord + Clone; // plus the existing native persistence bounds
    type Leaf: Clone;
    type Summary: Clone;

    // Ordinary typed functions, with checked failures:
    // validate(kind, key, leaf, summary), empty(kind),
    // singleton(kind, key, leaf), combine(kind, left, right).
}
```

This is an interface sketch, not an implementation signature to copy unchanged.
Persistence also requires `Eq`, `Debug`, `Send`, `Sync`, `Serialize` and
`DeserializeOwned` on the appropriate native types. Do not require `Copy` or
serialization of attempt-local evaluator parameters merely to simplify the port.

Use a validated model-local `IndexCode(u16)` in root/membership declarations and
stored root headers. It selects the family's finite native cases. A separate
associated `Kind` parameter threaded through every `Contract` is unnecessary:
preparation already resolves explicit codes against a selected compiled model.
Unknown/zero codes and incompatible root, key, leaf or summary combinations reject.
The codebook and its schemas belong to the native family and feed preparation and
catalogs from one definition; tools must not keep a second hand-maintained list.

The source ownership should be:

| Owner | Responsibility |
| --- | --- |
| `index` module | Small `NativeIndex` contract, `IndexCode` and bounded structural types; no list of every business summary. |
| Shared time-index module | Reusable financial and quote native types, existing complete-time algebra, canonical exact wire forms, and explicit time/financial capability adapters. |
| Model module | Its finite leaf/summary family and static codebook. The measurement family composes reusable financial/quote cases where needed and its own statistics case. |
| `tree` module | `FullKey<K>`, `Node<I>`, `Root<I>`, AVL/link maintenance, ordered coverage, checked depth and work accounting. |
| `native_codec` | Physical point-key encoding and strict generic envelope checks; decoding delegates native payload validation to the selected family. |
| `integrity` plus model checker | Complete structural observation and comparison to source-derived members and summary expectations. |

`FullKey<K>` orders `(business_key, source UUID, member slot)`. The suffix stays
engine-owned and must not be duplicated inside each model key. Existing UUIDs,
root addresses and membership addresses retain their roles.

Keep **structural subtree spans** separate from a business summary. The current
range fold obtains first/last times by matching `Aggregate` cases. A generic
tree instead maintains first/last business keys alongside height and links, with
independent checker verification. A custom summary must not have to mimic
financial `first`, `last`, `sum` or `count` fields to participate. Financial
summaries retain their own time endpoints because their algebra needs them.

`StoredValue<B>` owns `Root<B::Index>` and `Node<B::Index>`. The node envelope
remains one physical shape; it does not create new tables or a second node-key
namespace per summary. Native keys, leaves and summaries own their exact Serde
forms. In particular, a `TimeKey` newtype must keep canonical i64 strings rather
than accidentally emitting JSON numbers through a generic `K` field.

The first supplied families use `TimeKey`. Generic AVL comparisons and spans
must not inspect `.at`, but this gate does not certify a public composite-key
API. A future composite-key use must exercise its own native key, range wire,
comparator, prefix-bound semantics and source oracle. Do not ship an untested
`before_prefix` operation or manufacture greatest UUID/string suffixes now.

## Summary contract and model-author obligations

The writer calls a family's pure `empty`, `singleton` and ordered `combine`
functions. They must preserve the summary of concatenated ordered leaves. An
identity and associativity are obligations on the admitted bounded input domain;
the compiler cannot prove them. Commutativity and inverses are not required.
There is no claim that every useful predicate admits a fixed-width summary.

For measurement statistics, the dimension state is `Empty`, `Uniform(unit)` or
`Mixed`. Empty is identity; equal uniform tags combine to that tag; differing
tags or a mixed operand produce `Mixed`. Count/sum/extrema combine with their
ordinary checked rules. Transient mixed summaries may exist while an atomic
operation is staged; check the root's business unit invariant after settlement.
Never publish dimensionless numeric totals for a mixed final root.

Average, if exposed later, is derived from matching sum/count with explicit exact
division/rounding. It is not stored as an average-of-averages. Do not add squared
sum, approximation, unbounded sets or expression evaluation to anticipate uses.

A normal author using existing financial/quote roots chooses the supplied family
and reuses its code/schema helpers. A new summary author supplies only its bounded
native payloads, algebra, explicit descriptor/projection and independent source
oracle, plus ordinary memberships and invariants. They do not implement rotations,
storage transactions, authorization, receipts, interval routing or recovery.

## G4b windows, public reads and final-graph scope

Retain `TimeRange` and its exact inclusive/exclusive/unbounded meaning. A time
adapter maps those bounds to business-key coverage; UUID ties remain complete
timestamp groups. The generic fold uses ordered cached subtree summaries and
boundary leaves. It does not subtract arbitrary summaries.

Retain the specialized scalar prefix-sum path for existing financial reads when
only the sum is consumed. Generic full-summary folding must not force every
prefix query to calculate unused extrema. Ordinary time windows and the ordered
generic fold are separate entry points into the same tree and stored state.

Move public summary projection out of the global `Aggregate` match. The selected
native family supplies a strict, bounded projection for its declared root code;
the shared root API still enforces owner visibility, allowed operation, budget,
model identity and revisions. The measurement model declares `summary` and time
`range` and exposes their exact result schemas through its catalog. Existing
financial/latest response contracts remain explicit rather than inferred from
the fields present in a custom summary.

**G4c does not change `causal::evaluate`'s `&[i128]` result contract.** An index
having a `sum` field does not make it a dimensionally valid financial amount
input. The shared sum scheduler accepts only roots supported by an explicit
financial-time adapter. Adapters are ordinary compile-time traits/functions,
not numerical heuristics or unchecked casts. Existing final emission times,
prefix gates, bounded-window segment covers and original/staged time stabbing
remain unchanged for those reads. Keep the required generic bounds explicit at
their Rust call sites.

The new statistics use is authored direct membership plus settled root validation
and authorized root reads. Reactive consumption of statistics, custom predicates,
published-parent values and non-scalar results belongs to G4d. That later gate
must define typed query identities/results, invalidation and readiness together;
adding `serde_json::Value` to the formula input slice is not a substitute.

Likewise, a root ordered by `(item, time)` cannot use global timestamp stabbing or
time-based producer gates without a new declared order contract. Keeping its
summary generic does not establish its causal discovery algorithm.

## Coherent checkpoints without parallel engines

### G4c-a: replace the active representation

Port every production binding, member reconciliation, codec envelope, root read
and complete checker to the native-family representation. The existing financial
and quote implementations actively drive the single shared AVL from this point.
Remove the old `Kind`/`Leaf`/`Aggregate` dispatch after porting its callers; do not
leave an alternate tree behind or commit an unused generic helper as acceptance.

Preparation checks code/schema/allowed-operation agreement. Public root reads
use the same family definitions as storage. Scope this checkpoint to equivalent
existing formulas, time bounds and workloads; it is a useful structural checkpoint
but is **not yet acceptance of a new maintained summary**.

Acceptance: existing source-derived financial/quote cases, same-time complete
boundaries, native snapshot inventories, G4b exact windows/final-graph controls,
bytewise rejection rollback, replay/reopen, and representative selective/cascade
work checks. Explain any changed work counters rather than rebranding a constant
increase as new scalability. Preserve authorization and private-output rejection.

### G4c-b: use the extension through the ordinary product boundary

Add the small measurement binding with an authored fixture and a model-selected
CLI/HTTP workflow. It must use the same mutation, generic tree, native codec,
checker, root API, authority, receipts and storage lifecycle. No custom statistics
RPC or shadow cache is needed. Supply exact schemas and developer explanation
from the same native family declarations.

Acceptance: literal source scans derive unit tags/count/sum/extrema and expected
member/query inventories. Exercise insertion, equal times, negative values,
revalue, time/root moves, deletion, empty roots and windows, dimension rejection,
and both command orders for a valid final repair. Compare every real subtree's
cache to a scan of its expected leaves, including valid alternate AVL shapes.
Corrupt kind codes, key variants, payload/summary variants, spans and caches must
reject in check/startup/restore. Rejections preserve all application tables and
receipt absence. Verify replay, reopening, backup/restore and one authenticated
public range read plus an authority failure.

Add small algebra controls against a separate literal measurement scan and all
parenthesizations of short sequences. The existing financial complete-time oracle
must also compare grouped source arithmetic rather than merely call the writer's
new `combine` twice. Shared structural walking may be reused; summary expectations
must not reuse writer traversal/caches or the production family fold.

Only after this checkpoint does G4c claim a new maintained native summary. A
composite-key fixture or richer reactive-result gate can follow as a separately
chosen observable capability; neither is a prerequisite for the useful statistics
workflow above.

## Identity, formats and retained evidence

The proposed stored index codes, typed key envelopes and structural spans change
the native format. After G4b's format 5 is accepted, use store/codec **6** for
G4c-a and retain a matching G4b binary/store as an incompatible-open control.
Do not add an implicit populated-store migration. Bind native codebooks and
key/leaf/summary schemas into prepared model identity and maintain an explicit
behavior revision for comparator, summary, projection, causal adapter or invariant
changes. Revise every affected production binding when shared semantic contracts
change; a source hash alone is not the behavior identity.

Purely mechanical extraction could preserve an identical format if independently
demonstrated, but this concrete representation proposal changes it. Avoid two
gratuitous format bumps by settling the envelope before G4c-a. Adding the new
measurement binding in G4c-b then gives it its own model/behavior identity without
changing every other family's wire again. Preserve dated evidence rather than
rewriting old acceptance as if it had exercised generic native families.

## Algorithms retained and boundaries still open

Retain AVL insertion/deletion/rebalance, deterministic occurrence ties, linked
predecessor/successor maintenance, ordered subtree folding, charged depth guards,
explicit native validation and the accepted financial/quote algorithms. Test the
new extraction seams and summary laws; do not restart a broad proof of AVL balance.

The following are separate capabilities, not consequences of adding `NativeIndex`:

- Business-key uniqueness excludes UUID/member-slot ties and needs declared
  final-state checking. Preserve existing quote uniqueness; do not infer it for
  every root.
- Rank/select requires maintained occurrence counts and an explicit root order.
  Median-by-value requires value ordering; a time index does not provide it.
- Composite/partial-prefix bounds need a native comparator and exact before/after
  prefix contract. A public generic tuple language is not planned here.
- Arbitrary selection, latest/next dependency interaction, custom summary-driven
  topology and richer typed reactive values require G4d contracts.
- Distributed adapter conformance, general optimization/constraint solving and
  unbounded distinct-state summaries remain outside this gate.

Measured mutation work still includes affected memberships, summary width,
discovery, graph repairs, evaluations, validation and I/O. This proposal supplies
an extension boundary and two concrete maintained uses; it promises neither
universal monoid support nor constant-time solving.
