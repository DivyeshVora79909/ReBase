# Rust feasibility and stop boundary

**G4c accepted, October 23:** [native index families](34-native-index-extension.md)
drive one shared AVL and a fourth compiled model, dimensioned measurement.
Source 0.8.0 / store+codec 6 passes 109 debug/optimized Rust tests, 116 independent
native/local cases, 33 measurement and 111 invoicing HTTP mutations, and both
calculation/equipment workflows at 64 and 4,096 sources. Complete rollback,
authority, crash/reopen/restore, corrupt indexes and explicit format-5 rejection
are verified. G4a output-free validation and G4b exact reactive windows remain
accepted. Population/work limits are unchanged; the next gate is
[G4d-a declared published values](36-value-dependencies-gate.md). No new deployment
bundle, arbitrary native-summary reactivity or external service is claimed.

**G3e accepted, October 23:** the [0.6 deployment bundle](29-deployment-result.md)
builds from exported sources outside Git and runs all three compiled models with
the extracted tools. Two builds produce identical archive/executable bytes on
this host; all 159 payload checksums pass. Authenticated arithmetic, rollback,
replay, crash/restore, fresh issuer/template setup and nine rejected restores
pass. The selected local bundle goal is complete; deployment limits and future
capability gates remain explicit in the result.

**G3d accepted, October 23:** [settlement and linked refunds](28-settlement-refund-gate.md)
extend the same invoicing binding with explicit cash memberships, per-payment
refund capacity and complete-time balance/claim histories. All 76 Rust tests,
18 Python controls, 116 independent native/local cases and 111 HTTP mutations
pass. Rejections preserve every application-table byte and leave no receipt;
clean incompatible stores also preserve physical file bytes. Package 0.6 retains
the existing calculation/equipment identities and bounded 64/256/512 invoicing
envelope. G3e now verifies the deployment bundle; full accounting, rational FX
and distributed execution remain separate gates.

**G3c continuation:** [bounded invoicing](27-invoicing-gate.md) adds a third
compiled model in package 0.5, with 72 Rust tests and 58 independent HTTP mutation
scenarios, including 40 seeded history/rule stress batches, source-limit rejection,
recovery and copied-source execution. It proves 11555 → 9244 without duplicating
the engine. Payment/refund, full accounting and rational FX remain later gates.

**G3b continuation:** [typed parent parameters](26-parent-parameters-gate.md)
now connect declared authored rules to pure evaluation without persisted copies.
All 66 Rust tests and 116 independent cases pass; both prior 4,096-source model
stores pass reopening/integrity on copies. Existing behavior/store identities
remain unchanged; bounded invoicing is next. No multihop/derived input claim.

**G3a continuation:** [exact values](25-exact-values-gate.md) now implements
bounded rational multiplication and explicit rounding, with 7,396 independent
Fraction cases in both profiles, authenticated transaction acceptance, 63 Rust
tests and the unchanged 116-case independent native/local corpus. This closes
the numeric foundation, not the remaining accounting workflow or distributed
capabilities. Existing production model/store identities remain unchanged.

**G2 continuation:** [0.4 acceptance](24-population-scaling-result.md) closes
bounded population/index selection through both models at 4,096 sources, with
56 Rust tests, independent state checks, fixed-work rejection and recovery.
This does not establish unlimited cascades, general accounting or distributed
conformance. Earlier scope descriptions and evidence below remain dated.

**Current continuation:** [G1](21-compiled-model-result.md) accepts two distinct
native models through shared typed execution, causal settlement, authority,
storage and tools in 0.3.0. Forty-six optimized Rust tests and fresh independent
foundation/causal/local corpora pass. Both models retain the bounded runtime
envelope; larger populations and reactive candidate scaling are the next gate.
The older experiments and their limitations below remain dated.

**Deployable continuation:** D2–D6 now add transaction-scoped authority,
authenticated HTTP, verified storage lifecycle and reusable model/client tools.
The [release checkpoints](17-deployable-backend.md) own current scope and evidence;
the 0.2 release passes 39 Rust tests, six independent client controls and a
64-source HTTP workload with restart/archive/crash/restore checks. Earlier counts
below remain dated; see the [release result](18-release-result.md).

**Current executable scope also includes the October 22 native M1/M2/M4
experiment.** [Paper 12](12-native-slice.md) records its 68 cases / 93 operations,
real linked trees, settlement, complete snapshots, abort/reopen results and
13 passing integrated Rust tests. The sections below describe the earlier
October 21 proof and the separate research packets; their limits are dated.

**Executed locally on 2026-10-21.** This is a small semantic feasibility check.
It confirms that mature Rust value/schema/storage libraries can support the chosen
mechanics. It does not implement the complete proposed engine or measure speed.
Exact command output and fingerprints are retained in [feasibility.json](feasibility.json).

## What ran

From `rebase-next/`, with the local Rust 1.95.0 toolchain and locked dependencies:

```sh
cargo test --locked
cargo run --locked --example feasibility
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

Eight semantic tests passed, and the embedded example completed successfully.
The JSON Schema validator uses explicit format checking and offline reference
resolution. The example uses a real disposable redb database with its default
durability; it creates no persistent application database or network service.

## Facts checked

| Question | Evidence |
| --- | --- |
| Can the unusual complete-time summary survive regrouping? | Seven short histories, all three-segment split pairs and both parenthesizations agree with a separate raw scan that groups equal timestamps. Includes absent channels, real deficits and simultaneous cancellation. |
| Are historical guards different from final totals? | A positive final difference of `5` has a complete-time minimum of `-5`; independent minima return `0` and miss that violation. |
| Do exact values reject overflow? | Checked `i128` addition rejects overflow; reversed segments reject. Ordered combination is noncommutative. |
| Can declarations resolve actual dependency order? | A consumer with an alphabetically earlier name is evaluated after its source. Unknown inputs, duplicate fields and cycles reject. |
| Is the reader fold deterministic? | Descendants replace ancestors, incomparable candidates retain first declaration order, and empty candidates use owner fallback. |
| Can ordered partition merging remain bounded? | A standard `BinaryHeap` merges two authorized, disjoint sorted streams with ties; pagination matches independent sort order. Sparse existence is unknown at budget exhaustion, yes after continuation, and no only on full exhaustion. |
| Can staging avoid repeated persistence? | Five snapshot key loads, ten staged patches and five final dirty keys; staged reads see the final source. No-op creation/deletion and cached absence are tested. |
| Does real storage isolate/abort the staged result? | An old redb snapshot stays empty; a new snapshot sees source/two slots/two root summaries together. Aborting a later invalid mutation restores the entire original keyspace. Committed bytes survive close/reopen. |
| Can JSON Schema and exact transport compose? | The reusable Draft-2020-12 validator accepts the typed demo, rejects a floating price, an unknown calculated field and a malformed UUID. String price/nanoseconds bind into native exact integers. |
| Does a shared blind write suffice across isolation models? | A tiny conflict-set counterexample illustrates ordinary SI write skew and FoundationDB-style read/write conflict coverage. This is a mathematical model, not an executed distributed adapter test. |

The demo's final derived amount is **600 minor units**, from quantity `3` and
price `2.00`. Its five dirty keys are one fact, two separately addressed member
slots and two published root summaries. Slots retain source identity; roots use
explicit owner/slot addressing. The demo uses fixed well-formed UUIDs; it does not
test random ID generation or collision probability.

The byte overlay demonstrates persistence coalescing. It encodes each staged
patch for clarity; the proposed production workspace should keep typed nodes and
encode final dirty values once. The proof is not a throughput-optimized workspace.

## What does not need a new implementation here

AVL height bounds/rotation mechanics, heap-merge ordering, dictionary uniqueness,
UUID bit layouts and ordinary transactional atomicity already have established
algorithms or mature implementations. The proof composes existing library
infrastructure and tests only the semantic boundaries relevant to this redesign.
Reproving those established algorithms was unnecessary for the October 21
composition check. A later intrusive writer still needs focused link/rotation
tests against source scans; the native slice now supplies those. A complete
accounting demo remains a separate capability.

## Precise limits

- Root publications in the example each contain one leaf. There is no persistent
  AVL insertion/deletion, rank/range traversal or interval reverse index.
- The ordering test prepares local declared fields. There is no complete cross-record
  scheduler, historical move settlement, required-output lifecycle or feedback detector.
- Reader choice is a pure fold over a supplied dominance relation. There is no
  implemented principal DAG, closure repair, token verifier, revocation race or
  production authorized query planner.
- Merge streams are sorted slices, not distributed iterators. The proof supplies
  authorized partitions upstream and does not prove candidate scope completeness,
  snapshot pagination or arbitrary overlapping-root deduplication.
- The overlay provides point reads only. No staged range merge, predicate/phantom
  protection or backend-independent guard implementation has been exercised.
- redb normally serializes writers. Its result does not prove FoundationDB/TiKV
  conformance, distributed latency, root contention or multiwriter retry behavior.
- The summary uses one numeric channel and ordered `i64` keys. General composite
  comparators, decimal conversions/rounding, dynamic scales/tags and timestamp
  ranges require their own concrete implementation choices.
- The algebra is associative over integers. Checked fixed-width operations can
  reject a grouping with an overflowing intermediate sum; production needs a
  safe declared range or wider exact arithmetic. No wraparound is permitted.
- No RPC server, external effects, durable worker recovery, migration, UI port or
  performance benchmark is implemented. Historical ReBase tests were not rerun.

The meaningful conclusion is that **the core composition is feasible in Rust
without another broad framework**. Full-runtime correctness and performance are
separate questions. At the initial October 22 audit all 11 executable-source
fingerprints matched; the recorded checks above were reused, not rerun. The
[context audit](evidence/2026-10-22-context-audit.json) records that distinction.

The initial October 22 request required research and wireframes before planning.
The [scenario/gate register](08-research-workflow.md) owns those boundaries.
After the contracts and plan were ready, the user authorized autonomous S1–S5
completion; the resulting native capability is documented separately in paper 12.

The subsequent [M3/M5 research model](09-causal-settlement.md) is a separate
standard-library Python experiment: nine source states and all 36 valid orders
of five fixed calculation steps, checked against independent grouped arithmetic
and literal expectations. It checks logical output/query identity and rejection
predicates, not incremental repair, AVL structure, storage rollback, permissions
or UUID allocation. Its [evidence](evidence/2026-10-22-m3-m5.json) fingerprints the
new input. All 11 original Rust inputs matched at that stage and its tests were
not rerun by that packet; M3/M5 did not expand Rust executable scope.

[M6](10-independent-checker.md) adds a separate synthetic-snapshot checker,
reusing that Python source oracle without rerunning the 36-order campaign.
Five valid images passed, all 28 invalid-state controls rejected with their
expected obligation, and partial scope/budget exhaustion produced incomplete
results. Alternate balanced shapes are accepted; raw inventories, exact subtree
scans, interval endpoints and corrupt links are checked. The
[new evidence](evidence/2026-10-22-m6.json) records this bounded scope. It tests no
native tree writer, real snapshot export, direct reverse routes or storage
repair, and does not expand or rerun the original Rust executable proof.

The subsequent native packet changes `Cargo.toml`, `Cargo.lock` and `src/lib.rs`
and adds the fixed implementation. Its integrated suite reruns the eight existing
semantic tests alongside five new tests; the old feasibility example was not
rerun. The [new evidence](evidence/2026-10-22-native-slice.json) fingerprints the
current sources and explicitly retains the earlier evidence unchanged. The
native writer/real snapshot acceptance gap is closed for its simpler fixture;
M3/M5 lifecycle, public API and distributed acceptance remain separate gates.

P1 of the later local-prototype goal now closes native M3/M5 prefix/required-output
lifecycle for the bounded fixture. Its [result](15-causal-native-result.md) and
[evidence](evidence/2026-10-22-local-prototype-p1.json) record 39 causal cases / 55
operations plus the original 68 cases / 93 operations, complete rollback/reopen
checks and 14 integrated Rust tests. Earlier limitations in this paper describe
their dated experiment; public runtime/model tooling and distributed acceptance
remain separate from this P1 result.

P2–P4 subsequently complete the confirmed usable local-prototype goal. The
[current result](16-local-prototype-result.md) and
[final evidence](evidence/2026-10-22-local-prototype.json) add prepared model
tooling, a local process API, transactional public indexing/receipts, bounded
queries/cursors, demo and inspector. The integrated suite now has 27 tests;
the original and causal native corpora pass on the final source fingerprint.
Distributed/production capabilities remain outside that result. This paragraph
extends current executable scope without rewriting earlier dated evidence.
# Deployable continuation — October 22

The subsequent [D2 authority checkpoint](17-deployable-backend.md) adds real
tenant-local principal scopes, reader repair and indexed public candidates.
Its executed checks are recorded separately in
[D2 evidence](evidence/2026-10-22-d2-authority.json). Historical results below
retain their original scope; no distributed or production-capacity conclusion
follows from this bounded embedded implementation.
